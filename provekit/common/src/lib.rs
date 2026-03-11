pub mod file;
pub mod hash_config;
mod interner;
#[cfg(target_os = "macos")]
mod metal_ntt;
#[cfg(target_os = "macos")]
mod metal_sha2;
mod noir_proof_scheme;
pub mod optimize;
pub mod prefix_covector;
mod prover;
mod r1cs;
pub mod skyscraper;
pub mod sparse_matrix;
mod transcript_sponge;
pub mod utils;
mod verifier;
mod whir_r1cs;
pub mod witness;

use crate::{
    interner::{InternedFieldElement, Interner},
    sparse_matrix::{HydratedSparseMatrix, SparseMatrix},
};
pub use {
    acir::FieldElement as NoirElement,
    ark_bn254::Fr as FieldElement,
    hash_config::HashConfig,
    noir_proof_scheme::{MavrosSchemeData, NoirProof, NoirProofScheme, NoirSchemeData},
    prefix_covector::{OffsetCovector, PrefixCovector},
    prover::{MavrosProver, NoirProver, Prover},
    r1cs::R1CS,
    transcript_sponge::TranscriptSponge,
    verifier::Verifier,
    whir_r1cs::{WhirConfig, WhirR1CSProof, WhirR1CSScheme, WhirZkConfig},
    witness::PublicInputs,
};

/// Register provekit's custom implementations in whir's global registries.
///
/// Must be called once before any prove/verify operations.
/// Idempotent — safe to call multiple times.
pub fn register_ntt() {
    use std::{
        env,
        sync::{Arc, Once},
    };

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let ntt: Arc<dyn whir::algebra::ntt::ReedSolomon<FieldElement>> = {
            #[cfg(target_os = "macos")]
            {
                match metal_ntt::MetalBn254Ntt::new() {
                    Ok(metal) => {
                        let accelerator: Arc<
                            dyn whir::protocols::irs_commit::AcceleratedCommitter<FieldElement>,
                        > = Arc::new(metal);
                        whir::protocols::irs_commit::ACCELERATORS.insert(accelerator);
                        Arc::new(metal)
                    }
                    Err(err) => {
                        tracing::warn!(
                            "failed to initialize Metal BN254 NTT backend: {err}; falling back to \
                             CPU NTT"
                        );
                        Arc::new(whir::algebra::ntt::ArkNtt::<FieldElement>::default())
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                Arc::new(whir::algebra::ntt::ArkNtt::<FieldElement>::default())
            }
        };
        whir::algebra::ntt::NTT.insert(ntt);

        #[cfg(target_os = "macos")]
        if env::var_os("PROVEKIT_ENABLE_METAL_SHA2_ENGINE").is_some() {
            match metal_sha2::MetalSha2HashEngine::new() {
                Ok(engine) => {
                    let sha2: Arc<dyn whir::hash::HashEngine> = Arc::new(engine);
                    whir::hash::ENGINES.register(sha2);
                }
                Err(err) => tracing::warn!("failed to initialize Metal SHA2 backend: {err}"),
            }
        }

        whir::hash::ENGINES.register(Arc::new(skyscraper::SkyscraperHashEngine));
    });
}
