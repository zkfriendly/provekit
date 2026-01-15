pub mod blake3;
pub mod dummy;
pub mod keccak256;
pub mod poseidon;
pub mod sha256;
pub mod skyscraper;

mod pow_leading_zeros;

/// Macro to implement WHIR digest helper traits for a MerkleConfig.
/// This reduces boilerplate across hash implementations.
macro_rules! impl_whir_digest_traits {
    ($merkle_config:ty, $sponge:ty) => {
        impl whir::whir::domainsep::DigestDomainSeparator<$merkle_config>
            for spongefish::DomainSeparator<$sponge, $crate::FieldElement>
        {
            fn add_digest(self, label: &str) -> Self {
                <Self as spongefish::codecs::arkworks_algebra::FieldDomainSeparator<
                    $crate::FieldElement,
                >>::add_scalars(self, 1, label)
            }
        }

        impl whir::whir::utils::DigestToUnitSerialize<$merkle_config>
            for spongefish::ProverState<$sponge, $crate::FieldElement>
        {
            fn add_digest(
                &mut self,
                digest: $crate::FieldElement,
            ) -> spongefish::ProofResult<()> {
                <Self as spongefish::codecs::arkworks_algebra::FieldToUnitSerialize<
                    $crate::FieldElement,
                >>::add_scalars(self, &[digest])
            }
        }

        impl whir::whir::utils::DigestToUnitDeserialize<$merkle_config>
            for spongefish::VerifierState<'_, $sponge, $crate::FieldElement>
        {
            fn read_digest(&mut self) -> spongefish::ProofResult<$crate::FieldElement> {
                let [r] = <Self as spongefish::codecs::arkworks_algebra::FieldToUnitDeserialize<
                    $crate::FieldElement,
                >>::next_scalars(self)?;
                Ok(r)
            }
        }
    };
}

pub(crate) use impl_whir_digest_traits;
