use {
    crate::FieldElement,
    ark_bn254::Fr,
    ark_ff::{BigInt, PrimeField},
    light_poseidon::{Poseidon, PoseidonHasher},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zeroize::Zeroize,
};

fn to_fr(x: FieldElement) -> Fr {
    Fr::new(BigInt(x.into_bigint().0))
}

fn from_fr(x: Fr) -> FieldElement {
    FieldElement::new(x.into_bigint())
}

fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
}

type State = [FieldElement; 2];

#[derive(Clone, Zeroize)]
pub struct PoseidonPerm {
    state: State,
}

impl Default for PoseidonPerm {
    fn default() -> Self {
        Self { state: [FieldElement::from(0); 2] }
    }
}

impl AsRef<[FieldElement]> for PoseidonPerm {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for PoseidonPerm {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for PoseidonPerm {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state: [FieldElement::from(0), felt],
        }
    }

    fn permute(&mut self) {
        let mut poseidon = Poseidon::<Fr>::new_circom(2).expect("Poseidon init failed");
        let inputs: [Fr; 2] = [to_fr(self.state[0]), to_fr(self.state[1])];
        let hash = poseidon.hash(&inputs).expect("Poseidon hash failed");
        self.state = [self.state[1], from_fr(hash)];
    }
}

pub type PoseidonSponge = DuplexSponge<PoseidonPerm>;
