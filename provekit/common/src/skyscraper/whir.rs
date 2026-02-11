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
    zerocopy::IntoBytes,
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

    fn build_leaf_digests<L: AsRef<[FieldElement]> + Send + Sync>(
        _leaf_hash_param: &(),
        leaves: &[L],
    ) -> Result<Vec<FieldElement>, Error> {
        Ok(batch_build_leaf_digests(leaves))
    }

    fn build_non_leaf_nodes(
        _leaf_hash_param: &(),
        _two_to_one_hash_param: &(),
        leaf_digests: &[FieldElement],
    ) -> Result<Vec<FieldElement>, Error> {
        batch_build_non_leaf_nodes(leaf_digests)
    }
}

/// Compute leaf digests using block4's 4-way parallel compression.
///
/// Processes 4 leaves simultaneously at each step of the reduce chain,
/// exploiting block4's interleaved scalar + NEON SIMD squaring.
fn batch_build_leaf_digests<L: AsRef<[FieldElement]> + Send + Sync>(
    leaves: &[L],
) -> Vec<FieldElement> {
    // Each rayon task processes a chunk of leaves, batching groups of 4.
    const CHUNK: usize = 256;

    leaves
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

                    // Reduce all 4 chains in parallel using block4
                    let batch_results = skyscraper::block4::compress_reduce_4([
                        &raw_0, &raw_1, &raw_2, &raw_3,
                    ]);

                    // Convert results back to Montgomery form
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
        .collect()
}

/// Build the non-leaf nodes of a Merkle tree using batch Skyscraper hashing.
///
/// Uses `block4::compress_many` on aarch64 for ~2× faster hashing via
/// interleaved scalar + NEON SIMD Montgomery squaring. Falls back to
/// `simple::compress_many` on other architectures.
fn batch_build_non_leaf_nodes(
    leaf_digests: &[FieldElement],
) -> Result<Vec<FieldElement>, Error> {
    let leaf_nodes_size = leaf_digests.len();
    let non_leaf_nodes_size = leaf_nodes_size - 1;
    let tree_height = (leaf_nodes_size.trailing_zeros() as usize) + 1;

    let mut non_leaf_nodes = vec![FieldElement::default(); non_leaf_nodes_size];

    // Compute starting indices for each level (same layout as ark-crypto-primitives)
    let mut index = 0;
    let mut level_indices = Vec::with_capacity(tree_height - 1);
    for _ in 0..(tree_height - 1) {
        level_indices.push(index);
        index = 2 * index + 1; // left_child
    }

    // Bottom level: hash pairs of leaf digests
    // For Skyscraper, LeafInnerDigestConverter is identity, so leaf digests
    // can be used directly as inner digest inputs.
    {
        let start_index = level_indices.pop().unwrap();
        let upper_bound = 2 * start_index + 1;
        let level_nodes = &mut non_leaf_nodes[start_index..upper_bound];
        batch_compress_pairs(leaf_digests, level_nodes);
    }

    // Remaining levels: hash pairs of inner nodes
    level_indices.reverse();
    for &start_index in &level_indices {
        let upper_bound = 2 * start_index + 1;
        let level_size = upper_bound - start_index;
        // Split: current level is [start_index..upper_bound],
        // child level starts at [upper_bound..], but we only need the
        // first 2*level_size elements (the direct children).
        let (current_level, all_below) = non_leaf_nodes.split_at_mut(upper_bound);
        let level_nodes = &mut current_level[start_index..];
        let children = &all_below[..2 * level_size];
        batch_compress_pairs(children, level_nodes);
    }

    Ok(non_leaf_nodes)
}

/// Hash pairs of field elements using batch Skyscraper compression.
///
/// `children` is ordered as `[left0, right0, left1, right1, ...]`.
/// `parents` has one entry per pair (`parents.len() == children.len() / 2`).
///
/// Each rayon task converts a chunk from Montgomery form, hashes with
/// block4::compress_many (4-way SIMD on aarch64), then converts back.
fn batch_compress_pairs(children: &[FieldElement], parents: &mut [FieldElement]) {
    assert_eq!(children.len(), parents.len() * 2);

    // Process ~4096 hash pairs per rayon task (256 KiB input per chunk).
    const CHUNK: usize = 4096;

    parents
        .par_chunks_mut(CHUNK)
        .enumerate()
        .for_each(|(chunk_idx, parent_chunk)| {
            let n = parent_chunk.len();
            let child_start = chunk_idx * CHUNK * 2;
            let child_slice = &children[child_start..child_start + n * 2];

            // Convert children from Montgomery form to raw [u64; 4]
            let raw_messages: Vec<[u64; 4]> =
                child_slice.iter().map(|fe| fe.into_bigint().0).collect();

            // Prepare output buffer
            let mut raw_hashes: Vec<[u64; 4]> = vec![[0u64; 4]; n];

            // Batch compress using the fastest available implementation
            #[cfg(target_arch = "aarch64")]
            skyscraper::block4::compress_many(
                raw_messages.as_slice().as_bytes(),
                raw_hashes.as_mut_slice().as_mut_bytes(),
            );
            #[cfg(not(target_arch = "aarch64"))]
            skyscraper::simple::compress_many(
                raw_messages.as_slice().as_bytes(),
                raw_hashes.as_mut_slice().as_mut_bytes(),
            );

            // Convert results back to Montgomery form
            for (parent, raw) in parent_chunk.iter_mut().zip(raw_hashes) {
                *parent = FieldElement::new(BigInt(raw));
            }
        });
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
