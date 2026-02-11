use {
    crate::{skyscraper::SkyscraperSponge, FieldElement},
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{BigInt, PrimeField},
    rand08::Rng,
    rayon::prelude::*,
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
};

fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    let l64 = l.into_bigint().0;
    let r64 = r.into_bigint().0;
    let out = skyscraper::simple::compress(l64, r64);
    FieldElement::new(BigInt(out))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperCRH;

impl CRHScheme for SkyscraperCRH {
    type Input = [FieldElement];
    type Output = FieldElement;
    type Parameters = ();
    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }
    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        input: T,
    ) -> Result<Self::Output, Error> {
        let elements = input.borrow();
        if elements.is_empty() {
            return Err(Error::IncorrectInputLength(0));
        }
        // Convert all inputs to raw [u64; 4] form once, then reduce
        // entirely in raw form. This avoids redundant Montgomery conversions
        // on intermediate results (saves 2 field muls per step).
        let result = elements
            .iter()
            .map(|fe| fe.into_bigint().0)
            .reduce(|acc, next| skyscraper::simple::compress(acc, next))
            .unwrap();
        Ok(FieldElement::new(BigInt(result)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperTwoToOne;

impl TwoToOneCRHScheme for SkyscraperTwoToOne {
    type Input = FieldElement;
    type Output = FieldElement;
    type Parameters = ();
    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }
    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        Ok(compress(*l.borrow(), *r.borrow()))
    }
    fn compress<T: Borrow<Self::Output>>(
        p: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(p, l, r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkyscraperMerkleConfig;

impl Config for SkyscraperMerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = SkyscraperCRH;
    type TwoToOneHash = SkyscraperTwoToOne;
}

/// Batch leaf digest computation using block4's 4-way parallel compression.
///
/// Processes 4 leaves simultaneously at each step of the reduce chain,
/// exploiting block4's interleaved scalar + NEON SIMD squaring on AArch64.
/// Falls back to scalar `simple::compress` on other architectures.
impl whir::whir::merkle::BatchLeafDigest for SkyscraperMerkleConfig {
    fn batch_build_leaf_digests<L: AsRef<[FieldElement]> + Send + Sync>(
        _leaf_hash_param: &(),
        leaves: &[L],
    ) -> Result<Vec<FieldElement>, Error> {
        const CHUNK: usize = 256;

        let results = leaves
            .par_chunks(CHUNK)
            .flat_map_iter(|chunk| {
                let mut results = Vec::with_capacity(chunk.len());
                for group in chunk.chunks(4) {
                    #[cfg(target_arch = "aarch64")]
                    if group.len() == 4 {
                        // Convert all 4 leaves to raw [u64; 4] form
                        let raw_0: Vec<[u64; 4]> =
                            group[0].as_ref().iter().map(|fe| fe.into_bigint().0).collect();
                        let raw_1: Vec<[u64; 4]> =
                            group[1].as_ref().iter().map(|fe| fe.into_bigint().0).collect();
                        let raw_2: Vec<[u64; 4]> =
                            group[2].as_ref().iter().map(|fe| fe.into_bigint().0).collect();
                        let raw_3: Vec<[u64; 4]> =
                            group[3].as_ref().iter().map(|fe| fe.into_bigint().0).collect();

                        let batch_results = skyscraper::block4::compress_reduce_4([
                            &raw_0, &raw_1, &raw_2, &raw_3,
                        ]);

                        results.extend(
                            batch_results
                                .iter()
                                .map(|raw| FieldElement::new(BigInt(*raw))),
                        );
                        continue;
                    }
                    // Fallback: process leaves individually with simple::compress
                    for leaf in group {
                        let result = leaf
                            .as_ref()
                            .iter()
                            .map(|fe| fe.into_bigint().0)
                            .reduce(|acc, next| skyscraper::simple::compress(acc, next))
                            .unwrap();
                        results.push(FieldElement::new(BigInt(result)));
                    }
                }
                results
            })
            .collect();

        Ok(results)
    }
}

impl whir::whir::domainsep::DigestDomainSeparator<SkyscraperMerkleConfig>
    for DomainSeparator<SkyscraperSponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl whir::whir::utils::DigestToUnitSerialize<SkyscraperMerkleConfig>
    for ProverState<SkyscraperSponge, FieldElement>
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl whir::whir::utils::DigestToUnitDeserialize<SkyscraperMerkleConfig>
    for VerifierState<'_, SkyscraperSponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
