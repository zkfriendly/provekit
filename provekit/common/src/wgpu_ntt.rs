use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    marker::PhantomData,
    mem::size_of,
    sync::{mpsc, Arc, Mutex, OnceLock},
    time::Instant,
};

use ark_bn254::{Fr, FrConfig};
use ark_ff::{BigInt, Field, Fp, MontBackend};
use tracing::info;
use wgpu::util::DeviceExt;
use whir::{
    algebra::ntt::{generator, ArkNtt, ReedSolomon},
    engines::EngineId,
    hash::{Hash, SHA2},
    protocols::{
        irs_commit::{AcceleratedCommit, AcceleratedCommitter, MatrixRows},
        matrix_commit,
        merkle_tree,
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct WgpuBn254Ntt;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct GpuField {
    limbs: [u32; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct StageParams {
    total_butterflies: u32,
    row_len:           u32,
    half_len:          u32,
    step:              u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct Radix4Params {
    total_quads: u32,
    row_len:     u32,
    quarter_len: u32,
    outer_step:  u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct PackParams {
    poly_size:          u32,
    row_len:            u32,
    interleaving_depth: u32,
    message_length:     u32,
    coeff_bits:         u32,
    expansion_bits:     u32,
    total_elements:     u32,
    _padding:           u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct TransposeParams {
    rows:           u32,
    cols:           u32,
    total_elements: u32,
    _padding:       u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct FieldWordsParams {
    total_elements: u32,
    _padding:       [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct HashManyParams {
    size:                u32,
    count:               u32,
    input_offset_words:  u32,
    output_offset_words: u32,
}

struct RootTable {
    buffer: wgpu::Buffer,
}

struct EncodedMatrix {
    rows:   usize,
    cols:   usize,
    buffer: wgpu::Buffer,
}

struct WgpuNttEngine {
    adapter_info:   wgpu::AdapterInfo,
    device:         wgpu::Device,
    queue:          wgpu::Queue,
    pack:           wgpu::ComputePipeline,
    stage_radix2:   wgpu::ComputePipeline,
    stage_radix4:   wgpu::ComputePipeline,
    transpose:      wgpu::ComputePipeline,
    encode_words:   wgpu::ComputePipeline,
    sha256:         wgpu::ComputePipeline,
    roots_by_order: Mutex<HashMap<usize, Arc<RootTable>>>,
}

#[derive(Clone)]
struct WgpuMatrixRows {
    rows:   usize,
    cols:   usize,
    buffer: wgpu::Buffer,
    engine: Arc<WgpuNttEngine>,
}

static ENGINE: OnceLock<Result<Arc<WgpuNttEngine>, String>> = OnceLock::new();

impl WgpuBn254Ntt {
    #[cfg(test)]
    const DEFAULT_MIN_CODEWORD_LENGTH: usize = 32;
    #[cfg(not(test))]
    const DEFAULT_MIN_CODEWORD_LENGTH: usize = 1 << 19;

    const PACK_WORKGROUP_SIZE: u32 = 128;
    const STAGE_RADIX2_WORKGROUP_SIZE: u32 = 128;
    const STAGE_RADIX4_WORKGROUP_SIZE: u32 = 128;
    const TRANSPOSE_WORKGROUP_SIZE: u32 = 128;
    const ENCODE_WORDS_WORKGROUP_SIZE: u32 = 128;
    const SHA256_WORKGROUP_SIZE: u32 = 128;

    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_WGPU_NTT").is_some() {
            return Err("WGPU NTT disabled via PROVEKIT_DISABLE_WGPU_NTT".into());
        }

        match ENGINE.get_or_init(|| WgpuNttEngine::new().map(Arc::new)) {
            Ok(engine) => {
                info!(
                    backend = ?engine.adapter_info.backend,
                    device = engine.adapter_info.name,
                    driver = engine.adapter_info.driver,
                    "initialized WGPU BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init backend={:?} device={} driver={}",
                    engine.adapter_info.backend, engine.adapter_info.name, engine.adapter_info.driver
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    fn engine(&self) -> Result<&Arc<WgpuNttEngine>, String> {
        match ENGINE.get() {
            Some(Ok(engine)) => Ok(engine),
            Some(Err(err)) => Err(err.clone()),
            None => Err("wgpu engine not initialized".into()),
        }
    }

    fn min_codeword_length() -> usize {
        env::var("PROVEKIT_WGPU_NTT_MIN_CODEWORD_LENGTH")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(Self::DEFAULT_MIN_CODEWORD_LENGTH)
    }

    fn should_accelerate(
        codeword_length: usize,
        interleaved_coeffs: &[&[Fr]],
        leaf_hash_id: Option<EngineId>,
    ) -> bool {
        if interleaved_coeffs.is_empty() {
            return false;
        }
        if codeword_length <= 1
            || !codeword_length.is_power_of_two()
            || codeword_length < Self::min_codeword_length()
        {
            return false;
        }
        if let Some(leaf_hash_id) = leaf_hash_id {
            if leaf_hash_id != SHA2 {
                return false;
            }
        }
        true
    }

    fn cpu_encode(
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        ArkNtt::<Fr>::default().interleaved_encode(
            interleaved_coeffs,
            codeword_length,
            interleaving_depth,
        )
    }

    fn gpu_encode_artifact(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<EncodedMatrix, String> {
        let total_started = Instant::now();
        let engine = self.engine()?;

        if interleaved_coeffs.is_empty() {
            return Ok(EncodedMatrix {
                rows:   0,
                cols:   0,
                buffer: engine.empty_storage_buffer::<GpuField>(0, "empty-matrix"),
            });
        }
        if !Self::should_accelerate(codeword_length, interleaved_coeffs, None) {
            return Err("problem size below GPU threshold or unsupported".into());
        }

        let poly_size = interleaved_coeffs[0].len();
        if !poly_size.is_multiple_of(interleaving_depth) {
            return Err("interleaving depth does not divide polynomial size".into());
        }
        let message_length = poly_size / interleaving_depth;
        if !codeword_length.is_multiple_of(message_length) {
            return Err("codeword length is not a multiple of the message length".into());
        }

        let rows = interleaved_coeffs.len() * interleaving_depth;
        let total_size = rows * codeword_length;
        let total_butterflies = total_size / 2;
        let total_quads = total_size / 4;
        let total_size_u32 =
            u32::try_from(total_size).map_err(|_| "GPU launch exceeds current 32-bit grid limit")?;
        let total_butterflies_u32 = u32::try_from(total_butterflies)
            .map_err(|_| "GPU launch exceeds current 32-bit grid limit")?;
        let total_quads_u32 =
            u32::try_from(total_quads).map_err(|_| "GPU launch exceeds current 32-bit grid limit")?;

        trace_event(format_args!(
            "encode rows={} codeword_length={} interleaving_depth={} message_length={} polynomials={}",
            rows,
            codeword_length,
            interleaving_depth,
            message_length,
            interleaved_coeffs.len()
        ));

        let pack_started = Instant::now();
        let mut coeffs = Vec::with_capacity(interleaved_coeffs.len() * poly_size);
        for (poly_index, poly) in interleaved_coeffs.iter().enumerate() {
            debug_assert_eq!(poly_index * poly_size, coeffs.len());
            coeffs.extend(poly.iter().copied().map(fr_to_gpu));
        }
        let pack_elapsed = pack_started.elapsed();

        let roots_started = Instant::now();
        let roots = engine.root_table(codeword_length)?;
        let roots_elapsed = roots_started.elapsed();

        let coeffs = engine.storage_buffer_with_data(&coeffs, "coeffs", wgpu::BufferUsages::empty());
        let mut current = engine.empty_storage_buffer::<GpuField>(total_size, "ntt-current");
        let mut scratch = engine.empty_storage_buffer::<GpuField>(total_size, "ntt-scratch");

        let gpu_started = Instant::now();
        let mut encoder = engine
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-ntt-encode"),
            });

        let pack_params = PackParams {
            poly_size:          poly_size as u32,
            row_len:            codeword_length as u32,
            interleaving_depth: interleaving_depth as u32,
            message_length:     message_length as u32,
            coeff_bits:         message_length.trailing_zeros(),
            expansion_bits:     (codeword_length / message_length).trailing_zeros(),
            total_elements:     total_size_u32,
            _padding:           0,
        };
        let pack_params_buffer = engine.param_buffer(&pack_params, "pack-params");
        engine.dispatch_1d(
            &mut encoder,
            &engine.pack,
            &[
                engine.buffer_binding(&coeffs),
                engine.buffer_binding(&current),
                engine.buffer_binding(&pack_params_buffer),
            ],
            total_size_u32,
            Self::PACK_WORKGROUP_SIZE,
        );

        let stages = codeword_length.trailing_zeros() as usize;
        let mut stage = 0usize;
        while stage + 1 < stages {
            let quarter_len = 1usize << stage;
            let params = Radix4Params {
                total_quads: total_quads_u32,
                row_len:     codeword_length as u32,
                quarter_len: quarter_len as u32,
                outer_step:  (codeword_length / (quarter_len << 2)) as u32,
            };
            let params_buffer = engine.param_buffer(&params, "radix4-params");
            engine.dispatch_1d(
                &mut encoder,
                &engine.stage_radix4,
                &[
                    engine.buffer_binding(&current),
                    engine.buffer_binding(&scratch),
                    engine.buffer_binding(&roots.buffer),
                    engine.buffer_binding(&params_buffer),
                ],
                total_quads_u32,
                Self::STAGE_RADIX4_WORKGROUP_SIZE,
            );
            std::mem::swap(&mut current, &mut scratch);
            stage += 2;
        }

        if stage < stages {
            let len = 1usize << (stage + 1);
            let params = StageParams {
                total_butterflies: total_butterflies_u32,
                row_len:           codeword_length as u32,
                half_len:          (len / 2) as u32,
                step:              (codeword_length / len) as u32,
            };
            let params_buffer = engine.param_buffer(&params, "stage-params");
            engine.dispatch_1d(
                &mut encoder,
                &engine.stage_radix2,
                &[
                    engine.buffer_binding(&current),
                    engine.buffer_binding(&scratch),
                    engine.buffer_binding(&roots.buffer),
                    engine.buffer_binding(&params_buffer),
                ],
                total_butterflies_u32,
                Self::STAGE_RADIX2_WORKGROUP_SIZE,
            );
            std::mem::swap(&mut current, &mut scratch);
        }

        let transpose_params = TransposeParams {
            rows:           rows as u32,
            cols:           codeword_length as u32,
            total_elements: total_size_u32,
            _padding:       0,
        };
        let transpose_params_buffer = engine.param_buffer(&transpose_params, "transpose-params");
        engine.dispatch_1d(
            &mut encoder,
            &engine.transpose,
            &[
                engine.buffer_binding(&current),
                engine.buffer_binding(&scratch),
                engine.buffer_binding(&transpose_params_buffer),
            ],
            total_size_u32,
            Self::TRANSPOSE_WORKGROUP_SIZE,
        );

        engine.submit_and_wait(encoder.finish())?;
        let gpu_elapsed = gpu_started.elapsed();

        trace_event(format_args!(
            "encode timings codeword_length={} rows={} pack_us={} roots_us={} gpu_us={} total_us={}",
            codeword_length,
            rows,
            pack_elapsed.as_micros(),
            roots_elapsed.as_micros(),
            gpu_elapsed.as_micros(),
            total_started.elapsed().as_micros()
        ));

        Ok(EncodedMatrix {
            rows:   codeword_length,
            cols:   rows,
            buffer: scratch,
        })
    }

    fn gpu_commit_tree(
        &self,
        matrix: &EncodedMatrix,
        merkle_tree: &merkle_tree::Config,
    ) -> Result<matrix_commit::Witness, String> {
        let total_started = Instant::now();
        let engine = self.engine()?;
        if matrix.rows == 0 {
            return Ok(matrix_commit::Witness::from_nodes(vec![
                Hash::default();
                merkle_tree.num_nodes()
            ]));
        }
        if merkle_tree.num_leaves != matrix.rows {
            return Err(format!(
                "merkle tree leaf count mismatch: expected {}, got {}",
                merkle_tree.num_leaves, matrix.rows
            ));
        }
        if !merkle_tree
            .layers
            .iter()
            .all(|layer| layer.hash_id == SHA2)
        {
            return Err("GPU merkle path only supports SHA2 layers".into());
        }
        if 1usize << merkle_tree.layers.len() != matrix.rows {
            return Err("GPU merkle path requires an exact power-of-two leaf layer".into());
        }

        let total_elements = matrix.rows * matrix.cols;
        let total_elements_u32 = u32::try_from(total_elements)
            .map_err(|_| "GPU row hashing launch exceeds current 32-bit grid limit")?;
        let row_size = matrix.cols * size_of::<GpuField>();
        let word_count = total_elements * 8;
        let node_count = merkle_tree.num_nodes();
        let leaf_count = merkle_tree.num_leaves;
        let words_per_hash = size_of::<Hash>() / size_of::<u32>();
        let hash_bytes = size_of::<Hash>();

        let alloc_started = Instant::now();
        let encoded_words = engine.empty_storage_buffer::<u32>(word_count, "encoded-words");
        let nodes = engine.empty_storage_buffer::<u32>(node_count * words_per_hash, "merkle-nodes");
        let mut current_hashes =
            engine.empty_storage_buffer::<u32>(leaf_count * words_per_hash, "merkle-current");
        let mut next_hashes =
            engine.empty_storage_buffer::<u32>(leaf_count * words_per_hash, "merkle-next");
        let alloc_elapsed = alloc_started.elapsed();

        let encode_params = FieldWordsParams {
            total_elements: total_elements_u32,
            _padding:       [0; 3],
        };
        let encode_params_buffer = engine.param_buffer(&encode_params, "encode-words-params");
        let leaf_hash_params = HashManyParams {
            size:                row_size as u32,
            count:               leaf_count as u32,
            input_offset_words:  0,
            output_offset_words: 0,
        };
        let leaf_hash_params_buffer = engine.param_buffer(&leaf_hash_params, "leaf-hash-params");

        let gpu_started = Instant::now();
        let mut encoder = engine
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-commit-tree"),
            });

        self.dispatch_encode_words(
            engine,
            &mut encoder,
            matrix,
            &encoded_words,
            &encode_params_buffer,
            total_elements_u32,
        );
        self.dispatch_sha256(
            engine,
            &mut encoder,
            engine.buffer_binding(&encoded_words),
            engine.buffer_binding(&current_hashes),
            &leaf_hash_params_buffer,
            leaf_count as u32,
        );
        encoder.copy_buffer_to_buffer(
            &current_hashes,
            0,
            &nodes,
            0,
            (leaf_count * hash_bytes) as u64,
        );

        let mut next_offset = leaf_count;
        let mut previous_count = leaf_count;
        while previous_count > 1 {
            let parent_count = previous_count / 2;
            let parent_params = HashManyParams {
                size:                64,
                count:               parent_count as u32,
                input_offset_words:  0,
                output_offset_words: 0,
            };
            let parent_params_buffer = engine.param_buffer(&parent_params, "parent-hash-params");
            self.dispatch_sha256(
                engine,
                &mut encoder,
                engine.buffer_binding(&current_hashes),
                engine.buffer_binding(&next_hashes),
                &parent_params_buffer,
                parent_count as u32,
            );
            encoder.copy_buffer_to_buffer(
                &next_hashes,
                0,
                &nodes,
                (next_offset * hash_bytes) as u64,
                (parent_count * hash_bytes) as u64,
            );
            std::mem::swap(&mut current_hashes, &mut next_hashes);
            next_offset += parent_count;
            previous_count = parent_count;
        }

        engine.submit_and_wait(encoder.finish())?;
        let gpu_elapsed = gpu_started.elapsed();

        let readback_started = Instant::now();
        let nodes = engine.read_buffer::<Hash>(&nodes, node_count)?;
        let readback_elapsed = readback_started.elapsed();

        trace_event(format_args!(
            "hash timings rows={} cols={} alloc_us={} gpu_us={} readback_us={} total_us={}",
            matrix.rows,
            matrix.cols,
            alloc_elapsed.as_micros(),
            gpu_elapsed.as_micros(),
            readback_elapsed.as_micros(),
            total_started.elapsed().as_micros()
        ));

        Ok(matrix_commit::Witness::from_nodes(nodes))
    }

    #[cfg(test)]
    fn gpu_encode_row_words(&self, matrix: &EncodedMatrix) -> Result<Vec<u32>, String> {
        let engine = self.engine()?;
        let total_elements = matrix.rows * matrix.cols;
        let total_elements_u32 = u32::try_from(total_elements)
            .map_err(|_| "GPU row hashing launch exceeds current 32-bit grid limit")?;
        let encoded_words =
            engine.empty_storage_buffer::<u32>(total_elements * 8, "encoded-words-test");
        let encode_params = FieldWordsParams {
            total_elements: total_elements_u32,
            _padding:       [0; 3],
        };
        let encode_params_buffer = engine.param_buffer(&encode_params, "encode-words-params-test");
        let mut encoder = engine
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-encode-words-test"),
            });
        self.dispatch_encode_words(
            engine,
            &mut encoder,
            matrix,
            &encoded_words,
            &encode_params_buffer,
            total_elements_u32,
        );
        engine.submit_and_wait(encoder.finish())?;
        engine.read_buffer::<u32>(&encoded_words, total_elements * 8)
    }

    #[cfg(test)]
    fn gpu_hash_many_raw(&self, size: usize, input: &[u8]) -> Result<Vec<Hash>, String> {
        assert!(size.is_multiple_of(4));
        assert!(input.len().is_multiple_of(size));
        let engine = self.engine()?;
        let words = input
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>();
        let count = input.len() / size;
        let input_buffer =
            engine.storage_buffer_with_data(&words, "sha-input-words-test", wgpu::BufferUsages::empty());
        let output_buffer = engine.empty_storage_buffer::<u32>(count * 8, "sha-output-test");
        let params = HashManyParams {
            size:                size as u32,
            count:               count as u32,
            input_offset_words:  0,
            output_offset_words: 0,
        };
        let params_buffer = engine.param_buffer(&params, "sha-params-test");
        let mut encoder = engine
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-sha-test"),
            });
        self.dispatch_sha256(
            engine,
            &mut encoder,
            engine.buffer_binding(&input_buffer),
            engine.buffer_binding(&output_buffer),
            &params_buffer,
            count as u32,
        );
        engine.submit_and_wait(encoder.finish())?;
        engine.read_buffer::<Hash>(&output_buffer, count)
    }

    fn dispatch_encode_words(
        &self,
        engine: &WgpuNttEngine,
        encoder: &mut wgpu::CommandEncoder,
        matrix: &EncodedMatrix,
        encoded_words: &wgpu::Buffer,
        encode_params_buffer: &wgpu::Buffer,
        total_elements_u32: u32,
    ) {
        engine.dispatch_1d(
            encoder,
            &engine.encode_words,
            &[
                engine.buffer_binding(&matrix.buffer),
                engine.buffer_binding(encoded_words),
                engine.buffer_binding(encode_params_buffer),
            ],
            total_elements_u32,
            Self::ENCODE_WORDS_WORKGROUP_SIZE,
        );
    }

    fn dispatch_sha256(
        &self,
        engine: &WgpuNttEngine,
        encoder: &mut wgpu::CommandEncoder,
        input: wgpu::BindingResource<'_>,
        output: wgpu::BindingResource<'_>,
        params: &wgpu::Buffer,
        count: u32,
    ) {
        engine.dispatch_1d(
            encoder,
            &engine.sha256,
            &[input, output, engine.buffer_binding(params)],
            count,
            Self::SHA256_WORKGROUP_SIZE,
        );
    }

    fn gpu_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<Vec<Fr>, String> {
        let matrix =
            self.gpu_encode_artifact(interleaved_coeffs, codeword_length, interleaving_depth)?;
        let readback_started = Instant::now();
        let result = self
            .engine()?
            .read_buffer::<GpuField>(&matrix.buffer, matrix.rows * matrix.cols)?;
        let result = result.into_iter().map(gpu_to_fr).collect();
        trace_event(format_args!(
            "readback timings codeword_length={} rows={} readback_us={}",
            codeword_length,
            matrix.rows,
            readback_started.elapsed().as_micros()
        ));
        Ok(result)
    }
}

impl ReedSolomon<Fr> for WgpuBn254Ntt {
    fn interleaved_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        if !Self::should_accelerate(codeword_length, interleaved_coeffs, None) {
            return Self::cpu_encode(interleaved_coeffs, codeword_length, interleaving_depth);
        }
        self.gpu_encode(interleaved_coeffs, codeword_length, interleaving_depth)
            .unwrap_or_else(|err| {
                panic!(
                    "WGPU BN254 NTT execution failed for codeword_length={} interleaving_depth={}: {}",
                    codeword_length, interleaving_depth, err
                )
            })
    }
}

impl AcceleratedCommitter<Fr> for WgpuBn254Ntt {
    fn try_commit_interleaved(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
        leaf_hash_id: EngineId,
        merkle_tree: &merkle_tree::Config,
    ) -> Result<Option<AcceleratedCommit<Fr>>, String> {
        if !Self::should_accelerate(codeword_length, interleaved_coeffs, Some(leaf_hash_id)) {
            return Ok(None);
        }
        if merkle_tree.num_leaves != codeword_length
            || (1usize << merkle_tree.layers.len()) != merkle_tree.num_leaves
            || !merkle_tree.layers.iter().all(|layer| layer.hash_id == SHA2)
        {
            return Ok(None);
        }

        let matrix = self.gpu_encode_artifact(interleaved_coeffs, codeword_length, interleaving_depth)?;
        let matrix_witness = self.gpu_commit_tree(&matrix, merkle_tree)?;
        let rows = Arc::new(WgpuMatrixRows {
            rows: matrix.rows,
            cols: matrix.cols,
            buffer: matrix.buffer,
            engine: Arc::clone(self.engine()?),
        });
        Ok(Some(AcceleratedCommit {
            matrix:         rows,
            leaf_hashes:    None,
            matrix_witness: Some(matrix_witness),
        }))
    }
}

impl std::fmt::Debug for WgpuMatrixRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgpuMatrixRows")
            .field("rows", &self.rows)
            .field("cols", &self.cols)
            .finish()
    }
}

impl MatrixRows<Fr> for WgpuMatrixRows {
    fn len(&self) -> usize {
        self.rows * self.cols
    }

    fn read_rows(&self, indices: &[usize]) -> Vec<Fr> {
        for &row in indices {
            assert!(row < self.rows, "row index out of bounds");
        }
        let fields = self
            .engine
            .read_selected_rows::<GpuField>(&self.buffer, self.cols, indices)
            .unwrap_or_else(|err| panic!("WGPU matrix row read failed: {err}"));
        fields.into_iter().map(gpu_to_fr).collect()
    }
}

impl WgpuNttEngine {
    fn new() -> Result<Self, String> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
        let adapter =
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions::default()))
                .map_err(|err| err.to_string())?;
        let adapter_info = adapter.get_info();

        let desc = wgpu::DeviceDescriptor {
            label:                 Some("provekit-wgpu-ntt"),
            required_features:     wgpu::Features::empty(),
            required_limits:       adapter.limits(),
            experimental_features: wgpu::ExperimentalFeatures::disabled(),
            memory_hints:          wgpu::MemoryHints::Performance,
            trace:                 wgpu::Trace::Off,
        };
        let (device, queue) = pollster::block_on(adapter.request_device(&desc))
            .map_err(|err| err.to_string())?;

        let pack = Self::compute_pipeline(&device, "wgpu-pack", PACK_SHADER_SPV);
        let stage_radix2 =
            Self::compute_pipeline(&device, "wgpu-stage-radix2", STAGE_RADIX2_SHADER_SPV);
        let stage_radix4 =
            Self::compute_pipeline(&device, "wgpu-stage-radix4", STAGE_RADIX4_SHADER_SPV);
        let transpose = Self::compute_pipeline(&device, "wgpu-transpose", TRANSPOSE_SHADER_SPV);
        let encode_words =
            Self::compute_pipeline(&device, "wgpu-encode-words", ENCODE_WORDS_SHADER_SPV);
        let sha256 = Self::compute_pipeline_wgsl(&device, "wgpu-sha256", SHA256_SHADER_WGSL);
        Ok(Self {
            adapter_info,
            device,
            queue,
            pack,
            stage_radix2,
            stage_radix4,
            transpose,
            encode_words,
            sha256,
            roots_by_order: Mutex::new(HashMap::new()),
        })
    }

    fn compute_pipeline(
        device: &wgpu::Device,
        label: &str,
        spirv: &[u8],
    ) -> wgpu::ComputePipeline {
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label:  Some(label),
            source: wgpu::ShaderSource::SpirV(Cow::Owned(spirv_words(spirv))),
        });
        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label:               Some(label),
            layout:              None,
            module:              &module,
            entry_point:         Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache:               None,
        })
    }

    fn compute_pipeline_wgsl(
        device: &wgpu::Device,
        label: &str,
        source: &str,
    ) -> wgpu::ComputePipeline {
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label:  Some(label),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(source)),
        });
        device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label:               Some(label),
            layout:              None,
            module:              &module,
            entry_point:         Some("main"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache:               None,
        })
    }

    fn storage_buffer_with_data<T: Copy>(
        &self,
        values: &[T],
        label: &str,
        extra: wgpu::BufferUsages,
    ) -> wgpu::Buffer {
        self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label:    Some(label),
            contents: cast_slice(values),
            usage:    wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST
                | extra,
        })
    }

    fn empty_storage_buffer<T>(&self, len: usize, label: &str) -> wgpu::Buffer {
        self.device.create_buffer(&wgpu::BufferDescriptor {
            label:              Some(label),
            size:               (len * size_of::<T>()) as u64,
            usage:              wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        })
    }

    fn param_buffer<T: Copy>(&self, value: &T, label: &str) -> wgpu::Buffer {
        self.storage_buffer_with_data(std::slice::from_ref(value), label, wgpu::BufferUsages::empty())
    }

    fn buffer_binding<'a>(&self, buffer: &'a wgpu::Buffer) -> wgpu::BindingResource<'a> {
        buffer.as_entire_binding()
    }

    fn dispatch_1d(
        &self,
        encoder: &mut wgpu::CommandEncoder,
        pipeline: &wgpu::ComputePipeline,
        resources: &[wgpu::BindingResource<'_>],
        work_items: u32,
        workgroup_size: u32,
    ) {
        if work_items == 0 {
            return;
        }

        let layout = pipeline.get_bind_group_layout(0);
        let entries = resources
            .iter()
            .enumerate()
            .map(|(binding, resource)| wgpu::BindGroupEntry {
                binding:  binding as u32,
                resource: resource.clone(),
            })
            .collect::<Vec<_>>();
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label:   Some("wgpu-ntt-bind-group"),
            layout:  &layout,
            entries: &entries,
        });

        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label:            Some("wgpu-ntt-pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(pipeline);
        pass.set_bind_group(0, &bind_group, &[]);
        pass.dispatch_workgroups(work_items.div_ceil(workgroup_size), 1, 1);
    }

    fn submit_and_wait(&self, command_buffer: wgpu::CommandBuffer) -> Result<(), String> {
        self.queue.submit(Some(command_buffer));
        self.device
            .poll(wgpu::PollType::wait_indefinitely())
            .map_err(|err| err.to_string())?;
        Ok(())
    }

    fn map_read_buffer<T: Copy>(
        &self,
        staging: &wgpu::Buffer,
        len: usize,
    ) -> Result<Vec<T>, String> {
        let slice = staging.slice(..);
        let (tx, rx) = mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = tx.send(result);
        });
        self.device
            .poll(wgpu::PollType::wait_indefinitely())
            .map_err(|err| err.to_string())?;
        rx.recv()
            .map_err(|err| err.to_string())?
            .map_err(|err| err.to_string())?;

        let bytes = slice.get_mapped_range();
        let values = cast_bytes_to_vec::<T>(&bytes[..len * size_of::<T>()]);
        drop(bytes);
        staging.unmap();
        Ok(values)
    }

    fn read_buffer<T: Copy>(&self, source: &wgpu::Buffer, len: usize) -> Result<Vec<T>, String> {
        let size = (len * size_of::<T>()) as u64;
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label:              Some("wgpu-readback"),
            size,
            usage:              wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-readback-encoder"),
            });
        encoder.copy_buffer_to_buffer(source, 0, &staging, 0, size);
        self.submit_and_wait(encoder.finish())?;
        self.map_read_buffer::<T>(&staging, len)
    }

    fn read_selected_rows<T: Copy>(
        &self,
        source: &wgpu::Buffer,
        row_width: usize,
        indices: &[usize],
    ) -> Result<Vec<T>, String> {
        if indices.is_empty() {
            return Ok(Vec::new());
        }

        let row_size = row_width * size_of::<T>();
        let staging_size = (indices.len() * row_size) as u64;
        let staging = self.device.create_buffer(&wgpu::BufferDescriptor {
            label:              Some("wgpu-row-readback"),
            size:               staging_size,
            usage:              wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("wgpu-row-readback-encoder"),
            });

        for (slot, &row) in indices.iter().enumerate() {
            let src_offset = (row * row_size) as u64;
            let dst_offset = (slot * row_size) as u64;
            encoder.copy_buffer_to_buffer(source, src_offset, &staging, dst_offset, row_size as u64);
        }

        self.submit_and_wait(encoder.finish())?;
        self.map_read_buffer::<T>(&staging, indices.len() * row_width)
    }

    fn root_table(&self, codeword_length: usize) -> Result<Arc<RootTable>, String> {
        let mut cache = self.roots_by_order.lock().unwrap();
        if let Some(table) = cache.get(&codeword_length) {
            trace_event(format_args!("roots cache hit codeword_length={codeword_length}"));
            return Ok(Arc::clone(table));
        }

        let root = generator::<Fr>(codeword_length)
            .ok_or_else(|| format!("no primitive root for order {codeword_length}"))?;
        let mut roots = Vec::with_capacity(codeword_length / 2);
        let mut current = Fr::ONE;
        for _ in 0..(codeword_length / 2) {
            roots.push(fr_to_gpu(current));
            current *= root;
        }

        let table = Arc::new(RootTable {
            buffer: self.storage_buffer_with_data(&roots, "roots", wgpu::BufferUsages::empty()),
        });
        cache.insert(codeword_length, Arc::clone(&table));
        trace_event(format_args!("roots cache miss codeword_length={codeword_length}"));
        Ok(table)
    }
}

fn trace_event(args: std::fmt::Arguments<'_>) {
    if env::var_os("PROVEKIT_WGPU_NTT_TRACE").is_some() {
        eprintln!("[provekit-wgpu-ntt] {args}");
    }
}

fn fr_to_gpu(value: Fr) -> GpuField {
    let mut limbs = [0u32; 8];
    for (index, limb) in value.0 .0.iter().enumerate() {
        limbs[index * 2] = *limb as u32;
        limbs[index * 2 + 1] = (*limb >> 32) as u32;
    }
    GpuField { limbs }
}

fn gpu_to_fr(value: GpuField) -> Fr {
    let mut limbs = [0u64; 4];
    for (index, limb) in limbs.iter_mut().enumerate() {
        let lo = value.limbs[index * 2] as u64;
        let hi = value.limbs[index * 2 + 1] as u64;
        *limb = lo | (hi << 32);
    }
    Fp::<MontBackend<FrConfig, 4>, 4>(BigInt(limbs), PhantomData)
}

fn cast_slice<T: Copy>(values: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(values.as_ptr().cast::<u8>(), std::mem::size_of_val(values)) }
}

fn cast_bytes_to_vec<T: Copy>(bytes: &[u8]) -> Vec<T> {
    assert!(bytes.len().is_multiple_of(size_of::<T>()));
    let len = bytes.len() / size_of::<T>();
    unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<T>(), len) }.to_vec()
}

fn spirv_words(bytes: &[u8]) -> Vec<u32> {
    assert!(bytes.len().is_multiple_of(size_of::<u32>()));
    bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect()
}

const PACK_SHADER_SPV: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wgpu-pack.spv"));
const STAGE_RADIX2_SHADER_SPV: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/wgpu-stage-radix2.spv"));
const STAGE_RADIX4_SHADER_SPV: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/wgpu-stage-radix4.spv"));
const TRANSPOSE_SHADER_SPV: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/wgpu-transpose.spv"));
const ENCODE_WORDS_SHADER_SPV: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/wgpu-encode-words.spv"));
const SHA256_SHADER_WGSL: &str = include_str!("../shaders/wgpu_sha256.wgsl");

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::time::Instant;

    use super::WgpuBn254Ntt;
    use ark_bn254::Fr;
    use ark_ff::{AdditiveGroup, UniformRand};
    use sha2::Digest;
    use whir::{
        algebra::{
            embedding::Identity,
            ntt::{ntt_batch, transpose, ArkNtt, ReedSolomon},
        },
        hash::{Hash, HashEngine, Sha2, SHA2},
        protocols::{
            irs_commit::AcceleratedCommitter,
            matrix_commit::Encodable,
            merkle_tree,
        },
        transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
    };

    fn reference_interleaved_encode(
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Vec<Fr> {
        if interleaved_coeffs.is_empty() {
            return Vec::new();
        }

        let poly_size = interleaved_coeffs[0].len();
        let message_length = poly_size / interleaving_depth;
        let per_poly_size = codeword_length * interleaving_depth;
        let total_size = per_poly_size * interleaved_coeffs.len();

        let mut result = vec![Fr::ZERO; total_size];
        for (poly_index, poly) in interleaved_coeffs.iter().enumerate() {
            for (block_index, block) in poly.chunks_exact(message_length).enumerate() {
                let dst = poly_index * per_poly_size + block_index * codeword_length;
                result[dst..dst + message_length].copy_from_slice(block);
            }
        }

        ntt_batch(&mut result, codeword_length);
        transpose(
            &mut result,
            interleaved_coeffs.len() * interleaving_depth,
            codeword_length,
        );
        result
    }

    fn hash_rows_cpu(matrix: &[Fr], num_rows: usize, num_cols: usize) -> Vec<Hash> {
        let engine = Sha2::new();
        let mut encoder = <Fr as Encodable>::encoder();
        let bytes = encoder.encode(matrix);
        let mut out = vec![Hash::default(); num_rows];
        engine.hash_many(num_cols * Fr::encoded_size(), bytes, &mut out);
        out
    }

    fn hash_rows_from_words_cpu(words: &[u32], num_rows: usize, num_cols: usize) -> Vec<Hash> {
        let words_per_row = num_cols * 8;
        words
            .chunks_exact(words_per_row)
            .take(num_rows)
            .map(|row| {
                let mut bytes = Vec::with_capacity(words_per_row * 4);
                for &word in row {
                    bytes.extend_from_slice(&word.to_le_bytes());
                }
                let digest = sha2::Sha256::digest(&bytes);
                Hash(digest.into())
            })
            .collect()
    }

    #[test]
    fn wgpu_matches_cpu_for_small_case() {
        let gpu = WgpuBn254Ntt::new().unwrap();

        let mut rng = ark_std::test_rng();
        let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
        let cpu = reference_interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        let gpu = gpu.interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
        assert_eq!(cpu, gpu);
    }

    #[test]
    fn wgpu_sha256_matches_cpu_for_raw_messages() {
        let gpu = WgpuBn254Ntt::new().unwrap();
        for size in [64usize, 128, 256] {
            let count = 4usize;
            let input = (0..size * count)
                .map(|index| ((index * 17 + 3) & 0xff) as u8)
                .collect::<Vec<_>>();
            let actual = gpu.gpu_hash_many_raw(size, &input).unwrap();
            let mut expected = vec![Hash::default(); count];
            Sha2::new().hash_many(size, &input, &mut expected);
            assert_eq!(actual, expected, "raw sha mismatch for size={size}");
        }
    }

    #[test]
    fn wgpu_accelerated_commit_matches_cpu() {
        let gpu = WgpuBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs_a: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs_b: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs = [&coeffs_a[..], &coeffs_b[..]];
        let codeword_length = 32usize;
        let interleaving_depth = 2usize;

        let accelerated = gpu
            .try_commit_interleaved(
                &coeffs,
                codeword_length,
                interleaving_depth,
                SHA2,
                &merkle_tree::Config::with_hash(SHA2, codeword_length),
            )
            .unwrap()
            .unwrap();
        let cpu_matrix =
            reference_interleaved_encode(&coeffs, codeword_length, interleaving_depth);
        let expected_rows = [0usize, 3, 3, 17]
            .into_iter()
            .flat_map(|row| {
                let start = row * coeffs.len() * interleaving_depth;
                cpu_matrix[start..start + coeffs.len() * interleaving_depth]
                    .iter()
                    .copied()
            })
            .collect::<Vec<_>>();
        assert_eq!(accelerated.matrix.read_rows(&[0, 3, 3, 17]), expected_rows);

        let expected_hashes = hash_rows_cpu(
            &cpu_matrix,
            codeword_length,
            coeffs.len() * interleaving_depth,
        );
        let witness = accelerated.matrix_witness.as_ref().unwrap();
        assert_eq!(&witness.nodes()[..codeword_length], expected_hashes.as_slice());

        let merkle = merkle_tree::Config::with_hash(SHA2, codeword_length);
        let ds = DomainSeparator::protocol(&merkle)
            .session(&format!("Test at {}:{}", file!(), line!()))
            .instance(&Empty);
        let mut prover_state = ProverState::new_std(&ds);
        let cpu_witness = merkle.commit(&mut prover_state, expected_hashes);
        assert_eq!(witness.nodes(), cpu_witness.nodes());
    }

    #[test]
    fn wgpu_encode_words_matches_cpu_encoder() {
        let gpu = WgpuBn254Ntt::new().unwrap();
        let mut rng = ark_std::test_rng();
        let coeffs_a: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs_b: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
        let coeffs = [&coeffs_a[..], &coeffs_b[..]];
        let matrix = gpu
            .gpu_encode_artifact(&coeffs, 32, 2)
            .unwrap();
        let gpu_words = gpu.gpu_encode_row_words(&matrix).unwrap();

        let cpu_matrix = reference_interleaved_encode(&coeffs, 32, 2);
        let mut encoder = <Fr as Encodable>::encoder();
        let cpu_bytes = encoder.encode(&cpu_matrix).to_vec();
        let cpu_words = cpu_bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>();
        assert_eq!(gpu_words, cpu_words);
        assert_eq!(hash_rows_from_words_cpu(&gpu_words, 32, 4), hash_rows_cpu(&cpu_matrix, 32, 4));
    }

    #[test]
    fn irs_commit_roundtrip_uses_accelerated_wgpu_matrix() {
        crate::register_ntt();

        let config =
            whir::protocols::irs_commit::Config::<Identity<Fr>>::new(20.0, true, SHA2, 1, 32, 2, 0.5);
        let ds = DomainSeparator::protocol(&config)
            .session(&format!("Test at {}:{}", file!(), line!()))
            .instance(&Empty);

        let mut rng = ark_std::test_rng();
        let vector: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();

        let mut prover_state = ProverState::new_std(&ds);
        let witness = config.commit(&mut prover_state, &[vector.as_slice()]);
        assert!(witness.uses_accelerated_matrix());
        let evals = config.open(&mut prover_state, &[&witness]);
        let proof = prover_state.proof();

        let mut verifier_state = VerifierState::new_std(&ds, &proof);
        let commitment = config.receive_commitment(&mut verifier_state).unwrap();
        let verified = config.verify(&mut verifier_state, &[&commitment]).unwrap();
        assert_eq!(verified, evals);
        verifier_state.check_eof().unwrap();
    }

    #[test]
    #[ignore = "profiling benchmark"]
    fn benchmark_hot_shapes_against_cpu() {
        let gpu = WgpuBn254Ntt::new().unwrap();
        let cpu = ArkNtt::<Fr>::default();

        benchmark_shape("main-irs", &cpu, &gpu, 1, 1 << 20, 1 << 19, 8);
        benchmark_shape("small-batch", &cpu, &gpu, 21, 1 << 12, 1 << 11, 8);
    }

    fn benchmark_shape(
        label: &str,
        cpu: &ArkNtt<Fr>,
        gpu: &WgpuBn254Ntt,
        polys: usize,
        poly_size: usize,
        codeword_length: usize,
        interleaving_depth: usize,
    ) {
        let coeffs = (0..polys)
            .map(|poly| {
                (0..poly_size)
                    .map(|index| Fr::from((poly * poly_size + index + 1) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let refs = coeffs.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let cpu_started = Instant::now();
        let cpu_out = cpu.interleaved_encode(&refs, codeword_length, interleaving_depth);
        let cpu_elapsed = cpu_started.elapsed();

        let gpu_started = Instant::now();
        let gpu_out = gpu.interleaved_encode(&refs, codeword_length, interleaving_depth);
        let gpu_elapsed = gpu_started.elapsed();

        assert_eq!(cpu_out, gpu_out, "mismatch for benchmark shape {label}");
        println!(
            "benchmark {label}: polys={polys} poly_size={poly_size} codeword_length={codeword_length} interleaving_depth={interleaving_depth} cpu_ms={} gpu_ms={}",
            cpu_elapsed.as_millis(),
            gpu_elapsed.as_millis()
        );
    }
}
