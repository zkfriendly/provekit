use {
    crate::FieldElement,
    ark_ff::{BigInt, PrimeField},
    sha2::{Digest, Sha256 as Sha256Hasher},
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zeroize::Zeroize,
};

fn to_bytes(x: FieldElement) -> [u8; 32] {
    let limbs = x.into_bigint().0;
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
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
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state: [0.into(), felt],
        }
    }

    fn permute(&mut self) {
        let mut hasher = Sha256Hasher::new();
        hasher.update(&to_bytes(self.state[0]));
        hasher.update(&to_bytes(self.state[1]));
        let hash = hasher.finalize();
        let out: BigInt<4> = bigint_from_bytes_le(&hash);
        self.state = [self.state[1], FieldElement::new(out)];
    }
}

pub type Sha256Sponge = DuplexSponge<Sha256>;
