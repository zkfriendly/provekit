use {
    super::{
        field::gpu_to_fr,
        types::{
            DeviceMatrix, DeviceMerkleWitness, DeviceRows, EncodeFieldBytesParams, GpuField,
            HashManyParams,
        },
        MetalBn254Ntt,
    },
    ark_bn254::Fr,
    metal::{Buffer, MTLSize, NSRange, NSUInteger},
    std::{ffi::c_void, mem::size_of, sync::Arc},
    whir::{
        hash::Hash,
        protocols::{
            irs_commit::{AcceleratedCommit, AcceleratedCommitter, MatrixRows},
            matrix_commit::{Config as MatrixCommitConfig, Encodable},
            merkle_tree::AcceleratedWitness,
        },
    },
};

impl AcceleratedCommitter<Fr> for MetalBn254Ntt {
    fn try_commit_interleaved(
        &self,
        interleaved_coeffs: &[&[Fr]],
        matrix_commit: &MatrixCommitConfig<Fr>,
        interleaving_depth: usize,
    ) -> Result<Option<AcceleratedCommit<Fr>>, String> {
        let codeword_length = matrix_commit.num_rows();
        if !Self::supports_gpu_shape(
            codeword_length,
            interleaved_coeffs,
            Some(matrix_commit.leaf_hash_id),
        ) || !Self::supports_gpu_commit(matrix_commit)
        {
            return Ok(None);
        }

        let matrix = self.encode_matrix(interleaved_coeffs, codeword_length, interleaving_depth)?;
        let leaf_hashes = self.hash_rows_to_buffer(&matrix)?;
        let merkle_witness = self.build_merkle_witness(matrix_commit, &leaf_hashes)?;

        Ok(Some(AcceleratedCommit {
            matrix: Arc::new(DeviceRows {
                rows:   matrix.rows,
                cols:   matrix.cols,
                buffer: matrix.buffer,
            }),
            merkle_witness,
        }))
    }
}

impl MetalBn254Ntt {
    pub(super) fn hash_rows_to_buffer(
        &self,
        matrix: &DeviceMatrix,
    ) -> Result<Buffer, String> {
        if matrix.rows == 0 {
            return Ok(self.runtime()?.empty_buffer::<Hash>(0));
        }

        let runtime = self.runtime()?;
        let total_elements = matrix.rows * matrix.cols;
        let total_bytes = total_elements * Fr::encoded_size();
        let message_size = matrix.cols * Fr::encoded_size();
        if total_elements > u32::MAX as usize || message_size > u32::MAX as usize {
            return Err("GPU hash launch exceeds current 32-bit grid limit".into());
        }

        let encoded = runtime.empty_buffer::<u8>(total_bytes);
        let hashes = runtime.empty_buffer::<Hash>(matrix.rows);
        let encode_params = EncodeFieldBytesParams {
            total_elements: total_elements as u32,
        };
        let hash_params = HashManyParams {
            size:  message_size as u32,
            count: matrix.rows as u32,
        };
        let command_buffer = runtime.queue.new_command_buffer();

        let encode_encoder = command_buffer.new_compute_command_encoder();
        encode_encoder.set_compute_pipeline_state(&runtime.encode_bytes_pipeline);
        encode_encoder.set_buffer(0, Some(&matrix.buffer), 0);
        encode_encoder.set_buffer(1, Some(&encoded), 0);
        encode_encoder.set_bytes(
            2,
            size_of::<EncodeFieldBytesParams>() as NSUInteger,
            (&encode_params as *const EncodeFieldBytesParams).cast::<c_void>(),
        );
        let encode_threads =
            runtime.threads_per_threadgroup(&runtime.encode_bytes_pipeline, total_elements);
        encode_encoder.dispatch_threads(
            MTLSize {
                width:  total_elements as u64,
                height: 1,
                depth:  1,
            },
            encode_threads,
        );
        encode_encoder.end_encoding();

        let hash_encoder = command_buffer.new_compute_command_encoder();
        hash_encoder.set_compute_pipeline_state(&runtime.sha256_pipeline);
        hash_encoder.set_buffer(0, Some(&encoded), 0);
        hash_encoder.set_buffer(1, Some(&hashes), 0);
        hash_encoder.set_bytes(
            2,
            size_of::<HashManyParams>() as NSUInteger,
            (&hash_params as *const HashManyParams).cast::<c_void>(),
        );
        let hash_threads = runtime.threads_per_threadgroup(&runtime.sha256_pipeline, matrix.rows);
        hash_encoder.dispatch_threads(
            MTLSize {
                width:  matrix.rows as u64,
                height: 1,
                depth:  1,
            },
            hash_threads,
        );
        hash_encoder.end_encoding();

        command_buffer.commit();
        command_buffer.wait_until_completed();

        Ok(hashes)
    }

    pub(super) fn build_merkle_witness(
        &self,
        matrix_commit: &MatrixCommitConfig<Fr>,
        leaf_hashes: &Buffer,
    ) -> Result<Arc<dyn AcceleratedWitness>, String> {
        let runtime = self.runtime()?;
        let num_leaves = matrix_commit.num_rows();
        let leaf_capacity = 1usize << matrix_commit.merkle_tree.layers.len();
        let num_nodes = matrix_commit.merkle_tree.num_nodes();
        if leaf_capacity == 0 {
            return Err("invalid empty Merkle leaf capacity".into());
        }
        if num_nodes == 0 {
            return Err("invalid empty Merkle tree".into());
        }
        if num_leaves > leaf_capacity {
            return Err("Merkle config has fewer layers than leaves require".into());
        }
        if leaf_capacity > u32::MAX as usize {
            return Err("GPU Merkle launch exceeds current 32-bit grid limit".into());
        }

        let tree = runtime.empty_buffer::<Hash>(num_nodes);
        let command_buffer = runtime.queue.new_command_buffer();
        let blit = command_buffer.new_blit_command_encoder();
        blit.fill_buffer(
            &tree,
            NSRange::new(0, (num_nodes * size_of::<Hash>()) as u64),
            0,
        );
        if num_leaves != 0 {
            blit.copy_from_buffer(
                leaf_hashes,
                0,
                &tree,
                0,
                (num_leaves * size_of::<Hash>()) as u64,
            );
        }
        blit.end_encoding();

        let mut previous_offset = 0usize;
        let mut previous_len = leaf_capacity;
        for _ in matrix_commit.merkle_tree.layers.iter().rev() {
            let current_len = previous_len / 2;
            if current_len == 0 {
                break;
            }
            if current_len > u32::MAX as usize {
                return Err("GPU Merkle launch exceeds current 32-bit grid limit".into());
            }

            let params = HashManyParams {
                size:  64,
                count: current_len as u32,
            };
            let current_offset = previous_offset + previous_len;
            let encoder = command_buffer.new_compute_command_encoder();
            encoder.set_compute_pipeline_state(&runtime.sha256_pipeline);
            encoder.set_buffer(0, Some(&tree), (previous_offset * size_of::<Hash>()) as u64);
            encoder.set_buffer(1, Some(&tree), (current_offset * size_of::<Hash>()) as u64);
            encoder.set_bytes(
                2,
                size_of::<HashManyParams>() as NSUInteger,
                (&params as *const HashManyParams).cast::<c_void>(),
            );
            let threads = runtime.threads_per_threadgroup(&runtime.sha256_pipeline, current_len);
            encoder.dispatch_threads(
                MTLSize {
                    width:  current_len as u64,
                    height: 1,
                    depth:  1,
                },
                threads,
            );
            encoder.end_encoding();
            previous_offset = current_offset;
            previous_len = current_len;
        }

        command_buffer.commit();
        command_buffer.wait_until_completed();

        let root = runtime.buffer_slice::<Hash>(&tree, num_nodes)[num_nodes - 1];

        Ok(Arc::new(DeviceMerkleWitness {
            num_nodes,
            root,
            buffer: tree,
        }))
    }
}

impl AcceleratedWitness for DeviceMerkleWitness {
    fn num_nodes(&self) -> usize {
        self.num_nodes
    }

    fn root(&self) -> Hash {
        self.root
    }

    fn read_nodes(&self, indices: &[usize]) -> Vec<Hash> {
        let nodes = unsafe {
            std::slice::from_raw_parts(self.buffer.contents().cast::<Hash>(), self.num_nodes)
        };
        let mut out = Vec::with_capacity(indices.len());
        for &index in indices {
            assert!(index < self.num_nodes, "Merkle node index out of bounds");
            out.push(nodes[index]);
        }
        out
    }
}


impl std::fmt::Debug for DeviceRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceRows")
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish()
    }
}

impl MatrixRows<Fr> for DeviceRows {
    fn len(&self) -> usize {
        self.rows * self.cols
    }

    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        let mut out = Vec::with_capacity(indices.len() * self.cols);
        let fields = unsafe {
            std::slice::from_raw_parts(self.buffer.contents().cast::<GpuField>(), self.len())
        };
        for &row in indices {
            assert!(row < self.rows, "row index out of bounds");
            let start = row * self.cols;
            let end = start + self.cols;
            out.extend(fields[start..end].iter().copied().map(gpu_to_fr));
        }
        out
    }
}

impl std::fmt::Debug for DeviceMerkleWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceMerkleWitness")
            .field("num_nodes", &self.num_nodes)
            .field("root", &self.root)
            .finish()
    }
}
