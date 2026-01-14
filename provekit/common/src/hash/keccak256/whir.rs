use {
    crate::{hash::keccak256::Keccak256Sponge, FieldElement},
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{BigInt, PrimeField},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    sha3::{Digest, Keccak256},
    spongefish::{
        codecs::arkworks_algebra::{
            FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize,
        },
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
    zerocopy::transmute,
};

fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    let input: [u8; 64] = transmute!([l.into_bigint().0, r.into_bigint().0]);
    let hash: [u8; 32] = Keccak256::digest(&input).into();
    FieldElement::new(BigInt::new(transmute!(hash)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keccak256CRH;

impl CRHScheme for Keccak256CRH {
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
pub struct Keccak256TwoToOne;

impl TwoToOneCRHScheme for Keccak256TwoToOne {
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
pub struct Keccak256MerkleConfig;

impl Config for Keccak256MerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = Keccak256CRH;
    type TwoToOneHash = Keccak256TwoToOne;
}

impl whir::whir::domainsep::DigestDomainSeparator<Keccak256MerkleConfig>
    for DomainSeparator<Keccak256Sponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl whir::whir::utils::DigestToUnitSerialize<Keccak256MerkleConfig>
    for ProverState<Keccak256Sponge, FieldElement>
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl whir::whir::utils::DigestToUnitDeserialize<Keccak256MerkleConfig>
    for VerifierState<'_, Keccak256Sponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
