//! Dummy sponge for benchmarking - NOT SECURE, just fast.
//! Uses simple XOR operations instead of cryptographic hashing.

use {
    crate::FieldElement,
    ark_ff::BigInt,
    spongefish::duplex_sponge::{DuplexSponge, Permutation},
    zeroize::Zeroize,
};

fn bigint_from_bytes_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let limbs = bytes
        .chunks_exact(8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
        .collect::<Vec<_>>();
    BigInt::new(limbs.try_into().unwrap())
}

type State = [FieldElement; 2];

/// A dummy permutation that just does simple arithmetic.
/// WARNING: This is NOT cryptographically secure!
#[derive(Clone, Default, Zeroize)]
pub struct Dummy {
    state: State,
}

impl AsRef<[FieldElement]> for Dummy {
    fn as_ref(&self) -> &[FieldElement] {
        &self.state
    }
}

impl AsMut<[FieldElement]> for Dummy {
    fn as_mut(&mut self) -> &mut [FieldElement] {
        &mut self.state
    }
}

impl Permutation for Dummy {
    type U = FieldElement;
    const N: usize = 2;
    const R: usize = 1;

    fn new(iv: [u8; 32]) -> Self {
        let felt = FieldElement::new(bigint_from_bytes_le(&iv));
        Self {
            state: [0.into(), felt],
        }
    }

    #[inline(always)]
    fn permute(&mut self) {
        // Super simple "mixing" - just rotate and add
        // This is NOT secure, but it's fast
        let a = self.state[0];
        let b = self.state[1];
        // Simple linear combination - very fast
        self.state[0] = b;
        self.state[1] = a + b + FieldElement::from(1u64);
    }
}

pub type DummySponge = DuplexSponge<Dummy>;
