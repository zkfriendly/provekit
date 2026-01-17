use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
    sha2::{Digest, Sha256 as Sha256Hasher},
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
pub struct Sha256 {
    state: State,
}

impl AsRef<[FieldElement]> for Sha256 {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}
impl AsMut<[FieldElement]> for Sha256 {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Sha256 {
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
        // Rotate state: [l, r] -> [r, H(l || r)]
        let [l, r] = self.state;
        // Transmute both field elements to a single 64-byte array
        let input: [u8; 64] = transmute!([l.into_bigint().0, r.into_bigint().0]);
        self.state = [
            r,
            FieldElement::new(bigint_from_bytes_le(Sha256Hasher::digest(input).into())),
        ];
    }
}

pub type Sha256Sponge = DuplexSponge<Sha256>;
