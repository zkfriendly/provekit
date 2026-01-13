use {
    sha2::{Digest, Sha256 as Sha256Hasher},
    spongefish_pow::PowStrategy,
};

/// SHA-256 proof of work
#[derive(Clone, Copy)]
pub struct Sha256PoW {
    challenge: [u8; 32],
    bits:      f64,
}

impl PowStrategy for Sha256PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..64.0).contains(&bits), "bits must be smaller than 64");
        Self { challenge, bits }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let mut hasher = Sha256Hasher::new();
        hasher.update(&self.challenge);
        hasher.update(&nonce.to_le_bytes());
        let hash = hasher.finalize();

        let required_zeros = self.bits as u32;
        let full_bytes = required_zeros / 8;
        let remaining_bits = required_zeros % 8;

        for byte in hash.iter().take(full_bytes as usize) {
            if *byte != 0 {
                return false;
            }
        }

        if remaining_bits > 0 && (full_bytes as usize) < 32 {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[full_bytes as usize] & mask != 0 {
                return false;
            }
        }

        true
    }

    fn solve(&mut self) -> Option<u64> {
        for nonce in 0..u64::MAX {
            if self.check(nonce) {
                return Some(nonce);
            }
        }
        None
    }
}

#[test]
fn test_pow_sha256() {
    use {
        spongefish::{
            ByteDomainSeparator, BytesToUnitDeserialize, BytesToUnitSerialize, DefaultHash,
            DomainSeparator,
        },
        spongefish_pow::{PoWChallenge, PoWDomainSeparator},
    };

    const BITS: f64 = 10.0;

    let iopattern = DomainSeparator::<DefaultHash>::new("the proof of work lottery 🎰")
        .add_bytes(1, "something")
        .challenge_pow("rolling dices");

    let mut prover = iopattern.to_prover_state();
    prover.add_bytes(b"\0").expect("Invalid IOPattern");
    prover.challenge_pow::<Sha256PoW>(BITS).unwrap();

    let mut verifier = iopattern.to_verifier_state(prover.narg_string());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow::<Sha256PoW>(BITS).unwrap();
}
