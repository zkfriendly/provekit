//! Dummy Merkle tree config for benchmarking - NOT SECURE, just fast.
//! Uses simple addition instead of cryptographic hashing.

use {
    crate::{hash::dummy::DummySponge, FieldElement},
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    rand08::Rng,
    serde::{Deserialize, Serialize},
    std::borrow::Borrow,
};

/// Fast dummy compression - just adds the two inputs.
/// WARNING: This is NOT cryptographically secure!
#[inline(always)]
fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    l + r + FieldElement::from(1u64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummyCRH;

impl CRHScheme for DummyCRH {
    type Input = [FieldElement];
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    #[inline(always)]
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
pub struct DummyTwoToOne;

impl TwoToOneCRHScheme for DummyTwoToOne {
    type Input = FieldElement;
    type Output = FieldElement;
    type Parameters = ();

    fn setup<R: Rng>(_r: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    #[inline(always)]
    fn evaluate<T: Borrow<Self::Input>>(
        _: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        Ok(compress(*l.borrow(), *r.borrow()))
    }

    #[inline(always)]
    fn compress<T: Borrow<Self::Output>>(
        p: &Self::Parameters,
        l: T,
        r: T,
    ) -> Result<Self::Output, Error> {
        <Self as TwoToOneCRHScheme>::evaluate(p, l, r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummyMerkleConfig;

impl Config for DummyMerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = DummyCRH;
    type TwoToOneHash = DummyTwoToOne;
}

crate::hash::impl_whir_digest_traits!(DummyMerkleConfig, DummySponge);
