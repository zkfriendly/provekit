use {
    super::{
        field::{fr_to_gpu, gpu_to_fr},
        logging::trace_event,
        types::{DeviceMatrix, EncodeShape, GpuField, NttStageParams, TransposeParams},
        MetalBn254Ntt,
    },
    ark_bn254::Fr,
    metal::{MTLSize, NSUInteger},
    rayon::prelude::*,
    std::{ffi::c_void, mem::size_of},
};

impl MetalBn254Ntt {

    pub(super) fn gpu_encode(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<Vec<Fr>, String> {
        let matrix = self.encode_matrix(interleaved_coeffs, codeword_length, interleaving_depth)?;
        Ok(self
            .runtime()?
            .buffer_slice::<GpuField>(matrix.buffer.as_ref(), matrix.rows * matrix.cols)
            .iter()
            .copied()
            .map(gpu_to_fr)
            .collect())
    }

    pub(super) fn encode_matrix(
        &self,
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<DeviceMatrix, String> {
        let runtime = self.runtime()?;
        let shape = Self::encode_shape(interleaved_coeffs, codeword_length, interleaving_depth)?;
        if shape.total_elements == 0 {
            return Ok(DeviceMatrix {
                rows:   0,
                cols:   0,
                buffer: runtime.pooled_buffer::<GpuField>(0),
            });
        }

        trace_event(format_args!(
            "encode rows={} codeword_length={} interleaving_depth={} message_length={} \
             polynomials={} path=direct",
            shape.row_count,
            codeword_length,
            interleaving_depth,
            shape.message_length,
            interleaved_coeffs.len(),
        ));

        let current = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        runtime.zero_buffer::<GpuField>(current.as_ref(), shape.total_elements);
        pack_coefficients_into_buffer(
            runtime.buffer_slice_mut(current.as_ref(), shape.total_elements),
            interleaved_coeffs,
            shape,
            interleaving_depth,
        );
        let roots = runtime.roots_buffer(codeword_length)?;

        let scratch = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        let transposed = runtime.pooled_buffer::<GpuField>(shape.total_elements);
        let stage_count = codeword_length.trailing_zeros() as usize;
        let total_butterflies = shape.total_elements / 2;
        let stage_threads =
            runtime.threads_per_threadgroup(&runtime.ntt_stage_pipeline, total_butterflies);
        let transpose_threads =
            runtime.threads_per_threadgroup(&runtime.transpose_pipeline, shape.total_elements);
        let transpose_params = TransposeParams {
            rows:           shape.row_count as u32,
            cols:           shape.codeword_length as u32,
            total_elements: shape.total_elements as u32,
        };

        let command_buffer = runtime.queue.new_command_buffer();
        let stage_encoder = command_buffer.new_compute_command_encoder();
        stage_encoder.set_compute_pipeline_state(&runtime.ntt_stage_pipeline);

        let mut twiddle_offset = 0usize;
        let mut source_is_current = true;
        for stage in 0..stage_count {
            let stride = codeword_length >> (stage + 1);
            let params = NttStageParams {
                row_len:        shape.codeword_length as u32,
                stride:         stride as u32,
                twiddle_offset: twiddle_offset as u32,
                _pad0:          0,
            };
            if source_is_current {
                stage_encoder.set_buffer(0, Some(current.as_ref()), 0);
                stage_encoder.set_buffer(1, Some(scratch.as_ref()), 0);
            } else {
                stage_encoder.set_buffer(0, Some(scratch.as_ref()), 0);
                stage_encoder.set_buffer(1, Some(current.as_ref()), 0);
            }
            stage_encoder.set_buffer(2, Some(roots.as_ref()), 0);
            stage_encoder.set_bytes(
                3,
                size_of::<NttStageParams>() as NSUInteger,
                (&params as *const NttStageParams).cast::<c_void>(),
            );
            stage_encoder.dispatch_threads(
                MTLSize {
                    width:  total_butterflies as u64,
                    height: 1,
                    depth:  1,
                },
                stage_threads,
            );
            twiddle_offset += 1usize << stage;
            source_is_current = !source_is_current;
        }
        stage_encoder.end_encoding();

        let final_source = choose_final_buffer(stage_count, &current, &scratch);
        let transpose_encoder = command_buffer.new_compute_command_encoder();
        transpose_encoder.set_compute_pipeline_state(&runtime.transpose_pipeline);
        transpose_encoder.set_buffer(0, Some(final_source.as_ref()), 0);
        transpose_encoder.set_buffer(1, Some(transposed.as_ref()), 0);
        transpose_encoder.set_bytes(
            2,
            size_of::<TransposeParams>() as NSUInteger,
            (&transpose_params as *const TransposeParams).cast::<c_void>(),
        );
        transpose_encoder.dispatch_threads(
            MTLSize {
                width:  shape.total_elements as u64,
                height: 1,
                depth:  1,
            },
            transpose_threads,
        );
        transpose_encoder.end_encoding();

        command_buffer.commit();
        command_buffer.wait_until_completed();

        Ok(DeviceMatrix {
            rows:   shape.codeword_length,
            cols:   shape.row_count,
            buffer: transposed,
        })
    }

    pub(super) fn encode_shape(
        interleaved_coeffs: &[&[Fr]],
        codeword_length: usize,
        interleaving_depth: usize,
    ) -> Result<EncodeShape, String> {
        if interleaved_coeffs.is_empty() {
            return Ok(EncodeShape {
                row_count: 0,
                codeword_length,
                message_length: 0,
                total_elements: 0,
            });
        }
        if !Self::supports_gpu_shape(codeword_length, interleaved_coeffs, None) {
            return Err("problem shape unsupported for GPU path".into());
        }

        let polynomial_size = interleaved_coeffs[0].len();
        if interleaved_coeffs
            .iter()
            .any(|poly| poly.len() != polynomial_size)
        {
            return Err("all polynomials must have the same length".into());
        }
        if !polynomial_size.is_multiple_of(interleaving_depth) {
            return Err("interleaving depth does not divide polynomial size".into());
        }

        let message_length = polynomial_size / interleaving_depth;
        if !codeword_length.is_multiple_of(message_length) {
            return Err("codeword length is not a multiple of the message length".into());
        }

        let row_count = interleaved_coeffs.len() * interleaving_depth;
        let total_elements = row_count
            .checked_mul(codeword_length)
            .ok_or_else(|| "GPU encode launch exceeds current 32-bit grid limit".to_string())?;
        if total_elements > u32::MAX as usize {
            return Err("GPU encode launch exceeds current 32-bit grid limit".into());
        }

        Ok(EncodeShape {
            row_count,
            codeword_length,
            message_length,
            total_elements,
        })
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(super) fn gpu_mul_pairs(&self, lhs: &[Fr], rhs: &[Fr]) -> Result<Vec<Fr>, String> {
        if lhs.len() != rhs.len() {
            return Err("lhs/rhs length mismatch".into());
        }

        let runtime = self.runtime()?;
        let count = lhs.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > u32::MAX as usize {
            return Err("GPU field multiplication launch exceeds current 32-bit grid limit".into());
        }

        let lhs_buffer = runtime.pooled_buffer::<GpuField>(count);
        let rhs_buffer = runtime.pooled_buffer::<GpuField>(count);
        fill_linear_buffer(runtime.buffer_slice_mut(lhs_buffer.as_ref(), count), lhs);
        fill_linear_buffer(runtime.buffer_slice_mut(rhs_buffer.as_ref(), count), rhs);
        let output = runtime.pooled_buffer::<GpuField>(count);

        let command_buffer = runtime.queue.new_command_buffer();
        let encoder = command_buffer.new_compute_command_encoder();
        encoder.set_compute_pipeline_state(&runtime.field_mul_pipeline);
        encoder.set_buffer(0, Some(lhs_buffer.as_ref()), 0);
        encoder.set_buffer(1, Some(rhs_buffer.as_ref()), 0);
        encoder.set_buffer(2, Some(output.as_ref()), 0);
        let params = super::types::FieldMulParams {
            count: count as u32,
        };
        encoder.set_bytes(
            3,
            size_of::<super::types::FieldMulParams>() as NSUInteger,
            (&params as *const super::types::FieldMulParams).cast::<c_void>(),
        );
        let threads = runtime.threads_per_threadgroup(&runtime.field_mul_pipeline, count);
        encoder.dispatch_threads(
            MTLSize {
                width:  count as u64,
                height: 1,
                depth:  1,
            },
            threads,
        );
        encoder.end_encoding();
        command_buffer.commit();
        command_buffer.wait_until_completed();

        Ok(runtime
            .buffer_slice::<GpuField>(output.as_ref(), count)
            .iter()
            .copied()
            .map(gpu_to_fr)
            .collect())
    }
}

fn pack_coefficients_into_buffer(
    packed: &mut [GpuField],
    interleaved_coeffs: &[&[Fr]],
    shape: EncodeShape,
    interleaving_depth: usize,
) {
    packed
        .par_chunks_mut(shape.codeword_length)
        .enumerate()
        .for_each(|(row_index, row)| {
            let poly_index = row_index / interleaving_depth;
            let block_index = row_index % interleaving_depth;
            let block_start = block_index * shape.message_length;
            let block_end = block_start + shape.message_length;
            for (dst, &coeff) in row[..shape.message_length]
                .iter_mut()
                .zip(&interleaved_coeffs[poly_index][block_start..block_end])
            {
                *dst = fr_to_gpu(coeff);
            }
        });
}

#[cfg(all(test, target_os = "macos"))]
fn fill_linear_buffer(dst: &mut [GpuField], src: &[Fr]) {
    dst.par_iter_mut()
        .enumerate()
        .for_each(|(index, dst)| *dst = fr_to_gpu(src[index]));
}

fn choose_final_buffer<'a>(
    stage_count: usize,
    current: &'a super::engine::PooledBuffer,
    scratch: &'a super::engine::PooledBuffer,
) -> &'a super::engine::PooledBuffer {
    if stage_count.is_multiple_of(2) {
        current
    } else {
        scratch
    }
}
