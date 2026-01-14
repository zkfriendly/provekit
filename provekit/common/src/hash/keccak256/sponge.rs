use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
    sha3::{Digest, Keccak256 as Keccak256Hasher},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zerocopy::transmute,
    zeroize::Zeroize,
};

#[inline]
fn bigint_from_bytes_le(bytes: [u8; 32]) -> BigInt<4> {
    BigInt::new(transmute!(bytes))
}

type State = [FieldElement; 2];

#[derive(Clone, Default, Zeroize)]
pub struct Keccak256 {
    state: State,
}

impl AsRef<[FieldElement]> for Keccak256 {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Keccak256 {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Keccak256 {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(iv));
        Self {
            state: [0.into(), felt],
        }
    }

    fn permute(&mut self) {
        let [l, r] = self.state;
        let input: [u8; 64] = transmute!([l.into_bigint().0, r.into_bigint().0]);
        self.state = [r, FieldElement::new(bigint_from_bytes_le(Keccak256Hasher::digest(input).into()))];
    }
}

pub type Keccak256Sponge = DuplexSponge<Keccak256>;
