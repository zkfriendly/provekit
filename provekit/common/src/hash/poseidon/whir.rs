use {
    crate::{hash::poseidon::PoseidonSponge, FieldElement},
    ark_bn254::Fr,
    ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter},
        Error,
    },
    ark_ff::{BigInt, PrimeField},
    light_poseidon::{Poseidon, PoseidonHasher},
    rand08::Rng,
    serde::{Deserialize, Serialize},
    spongefish::{
        codecs::arkworks_algebra::{FieldDomainSeparator, FieldToUnitDeserialize, FieldToUnitSerialize},
        DomainSeparator, ProofResult, ProverState, VerifierState,
    },
    std::borrow::Borrow,
};

fn to_fr(x: FieldElement) -> Fr {
    Fr::new(BigInt(x.into_bigint().0))
}

fn from_fr(x: Fr) -> FieldElement {
    FieldElement::new(x.into_bigint())
}

fn compress(l: FieldElement, r: FieldElement) -> FieldElement {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).expect("Poseidon init failed");
    let hash = poseidon.hash(&[to_fr(l), to_fr(r)]).expect("Poseidon hash failed");
    from_fr(hash)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoseidonCRH;

impl CRHScheme for PoseidonCRH {
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
pub struct PoseidonTwoToOne;

impl TwoToOneCRHScheme for PoseidonTwoToOne {
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
pub struct PoseidonMerkleConfig;

impl Config for PoseidonMerkleConfig {
    type Leaf = [FieldElement];
    type LeafDigest = FieldElement;
    type LeafInnerDigestConverter = IdentityDigestConverter<FieldElement>;
    type InnerDigest = FieldElement;
    type LeafHash = PoseidonCRH;
    type TwoToOneHash = PoseidonTwoToOne;
}

impl whir::whir::domainsep::DigestDomainSeparator<PoseidonMerkleConfig>
    for DomainSeparator<PoseidonSponge, FieldElement>
{
    fn add_digest(self, label: &str) -> Self {
        <Self as FieldDomainSeparator<FieldElement>>::add_scalars(self, 1, label)
    }
}

impl whir::whir::utils::DigestToUnitSerialize<PoseidonMerkleConfig>
    for ProverState<PoseidonSponge, FieldElement>
{
    fn add_digest(&mut self, digest: FieldElement) -> ProofResult<()> {
        self.add_scalars(&[digest])
    }
}

impl whir::whir::utils::DigestToUnitDeserialize<PoseidonMerkleConfig>
    for VerifierState<'_, PoseidonSponge, FieldElement>
{
    fn read_digest(&mut self) -> ProofResult<FieldElement> {
        let [r] = self.next_scalars()?;
        Ok(r)
    }
}
