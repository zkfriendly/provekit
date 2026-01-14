use {
    sha2::{Digest, Sha256 as Sha256Hasher},
    spongefish_pow::PowStrategy,
};

/// SHA-256 proof of work
#[derive(Clone, Copy)]
pub struct Sha256PoW {
    challenge: [u8; 32],
    required_zeros: u32,
}

impl PowStrategy for Sha256PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..64.0).contains(&bits), "bits must be smaller than 64");
        Self { challenge, required_zeros: bits as u32 }
    }

    fn check(&mut self, nonce: u64) -> bool {
        let hash = Sha256Hasher::new()
            .chain_update(&self.challenge)
            .chain_update(&nonce.to_le_bytes())
            .finalize();

        // Convert first 8 bytes to big-endian u64 and count leading zeros
        // leading_zeros() compiles to a single CPU instruction (lzcnt/clz)
        u64::from_be_bytes(hash[..8].try_into().unwrap()).leading_zeros() >= self.required_zeros
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
