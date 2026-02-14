use {
    crate::{skyscraper::SkyscraperSponge, FieldElement},
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{BigInt, PrimeField},
    rand08::Rng,
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
        input
            .borrow()
            .iter()
            .copied()
            .reduce(compress)
            .ok_or(Error::IncorrectInputLength(0))
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

impl whir::whir::merkle::BatchLeafDigest for SkyscraperMerkleConfig {
    fn batch_build_leaf_digests<L: AsRef<Self::Leaf> + Send + Sync>(
        _leaf_hash_param: &<SkyscraperCRH as CRHScheme>::Parameters,
        leaves: &[L],
    ) -> Result<Vec<Self::LeafDigest>, Error>
    where
        Self: Sized,
    {
        if leaves.is_empty() {
            return Ok(vec![]);
        }

        let leaf_len = leaves[0].as_ref().len();
        if leaf_len == 0 {
            return Err(Error::IncorrectInputLength(0));
        }

        // Single-element leaves: just return them directly.
        if leaf_len == 1 {
            return Ok(leaves.iter().map(|l| l.as_ref()[0]).collect());
        }

        // Process leaves in parallel chunks, using SIMD batching within each chunk.
        // Within each chunk, instead of hashing each leaf sequentially, we batch all
        // compress calls at the same reduction step across leaves so that
        // compress_many can exploit SIMD parallelism (e.g. block4 on aarch64).
        use rayon::prelude::*;
        let results: Vec<FieldElement> = leaves
            .par_chunks(256)
            .flat_map_iter(|chunk| simd_hash_chunk(chunk))
            .collect();

        Ok(results)
    }
}

/// Batch-hash a chunk of leaves using SIMD-accelerated `compress_many`.
///
/// The CRH folds a leaf `[a, b, c, d, …]` as `compress(…compress(compress(a,
/// b), c)…, last)`. Instead of hashing each leaf independently, we batch the
/// compress calls *across* all leaves at the same fold step so that
/// `compress_many` can use SIMD to process multiple compressions in parallel
/// (4-wide on aarch64 via `block4`).
fn simd_hash_chunk<L: AsRef<[FieldElement]>>(leaves: &[L]) -> Vec<FieldElement> {
    let n = leaves.len();
    let leaf_len = leaves[0].as_ref().len();

    // Initialise accumulators with the first element of each leaf (as raw [u64;
    // 4]).
    let mut accs: Vec<[u64; 4]> = leaves
        .iter()
        .map(|l| l.as_ref()[0].into_bigint().0)
        .collect();

    // Reusable I/O buffers for compress_many.
    let mut messages: Vec<[[u64; 4]; 2]> = vec![[[0u64; 4]; 2]; n];
    let mut hashes: Vec<[u64; 4]> = vec![[0u64; 4]; n];

    for step in 1..leaf_len {
        // Build message pairs: (accumulator, next leaf element) for every leaf.
        for i in 0..n {
            messages[i] = [accs[i], leaves[i].as_ref()[step].into_bigint().0];
        }

        // SAFETY: [u64; 4] and [[u64; 4]; 2] have no padding and are layout-
        // compatible with their byte representations. compress_many expects
        // messages as &[u8] of layout [[[u64;4];2]] and hashes as &mut [u8] of
        // layout [[u64;4]].
        let msg_bytes = unsafe {
            std::slice::from_raw_parts(
                messages.as_ptr().cast::<u8>(),
                n * std::mem::size_of::<[[u64; 4]; 2]>(),
            )
        };
        let hash_bytes = unsafe {
            std::slice::from_raw_parts_mut(
                hashes.as_mut_ptr().cast::<u8>(),
                n * std::mem::size_of::<[u64; 4]>(),
            )
        };

        // Use the fastest available compress_many for this platform.
        #[cfg(target_arch = "aarch64")]
        skyscraper::block4::compress_many(msg_bytes, hash_bytes);
        #[cfg(not(target_arch = "aarch64"))]
        skyscraper::simple::compress_many(msg_bytes, hash_bytes);

        accs.copy_from_slice(&hashes);
    }

    // Convert raw limbs back to FieldElement.
    accs.into_iter()
        .map(|a| FieldElement::new(BigInt(a)))
        .collect()
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
