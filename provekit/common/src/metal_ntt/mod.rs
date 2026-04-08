mod commit;
mod encode;
mod engine;
mod field;
mod logging;
mod types;

use {
    self::{engine::MetalRuntime, logging::trace_event},
    ark_bn254::Fr,
    std::{
        env,
        sync::{Arc, OnceLock},
    },
    tracing::info,
    whir::{
        engines::EngineId,
        hash::SHA2,
        protocols::matrix_commit::Config as MatrixCommitConfig,
    },
};

#[derive(Clone, Copy, Debug, Default)]
pub struct MetalBn254Ntt;

static RUNTIME: OnceLock<Result<Arc<MetalRuntime>, String>> = OnceLock::new();

impl MetalBn254Ntt {
    pub fn new() -> Result<Self, String> {
        if env::var_os("PROVEKIT_DISABLE_METAL_NTT").is_some() {
            return Err("Metal NTT disabled via PROVEKIT_DISABLE_METAL_NTT".into());
        }

        match RUNTIME.get_or_init(|| MetalRuntime::new().map(Arc::new)) {
            Ok(runtime) => {
                info!(
                    device = runtime.device.name(),
                    thread_execution_width = runtime.ntt_stage_pipeline.thread_execution_width(),
                    max_total_threads_per_threadgroup = runtime
                        .ntt_stage_pipeline
                        .max_total_threads_per_threadgroup(),
                    "initialized Metal BN254 NTT backend"
                );
                trace_event(format_args!(
                    "init device={} thread_execution_width={} max_total_threads_per_threadgroup={}",
                    runtime.device.name(),
                    runtime.ntt_stage_pipeline.thread_execution_width(),
                    runtime
                        .ntt_stage_pipeline
                        .max_total_threads_per_threadgroup(),
                ));
                Ok(Self)
            }
            Err(err) => Err(err.clone()),
        }
    }

    fn runtime(&self) -> Result<&Arc<MetalRuntime>, String> {
        match RUNTIME.get() {
            Some(Ok(runtime)) => Ok(runtime),
            Some(Err(err)) => Err(err.clone()),
            None => Err("metal runtime not initialized".into()),
        }
    }

    fn supports_gpu_shape(
        codeword_length: usize,
        interleaved_coeffs: &[&[Fr]],
        leaf_hash_id: Option<EngineId>,
    ) -> bool {
        if interleaved_coeffs.is_empty() {
            return false;
        }
        if codeword_length <= 1 || !codeword_length.is_power_of_two() {
            return false;
        }
        if let Some(leaf_hash_id) = leaf_hash_id {
            if leaf_hash_id != SHA2 {
                return false;
            }
        }
        true
    }

    fn supports_gpu_commit(matrix_commit: &MatrixCommitConfig<Fr>) -> bool {
        matrix_commit.leaf_hash_id == SHA2
            && matrix_commit
                .merkle_tree
                .layers
                .iter()
                .all(|layer| layer.hash_id == SHA2)
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "tests.rs"]
mod tests;
