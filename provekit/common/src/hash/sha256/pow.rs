use {
    crate::hash::pow_leading_zeros,
    sha2::{Digest, Sha256 as Sha256Hasher},
    spongefish_pow::PowStrategy,
};

/// SHA-256 proof of work
#[derive(Clone, Copy)]
pub struct Sha256PoW {
    challenge: [u8; 32],
    bits: u32,
}

impl Sha256PoW {
    fn check_pow(&self, nonce: u64) -> bool {
        let hash = Sha256Hasher::new()
            .chain_update(&self.challenge)
            .chain_update(&nonce.to_le_bytes())
            .finalize();
        u64::from_be_bytes(hash[..8].try_into().unwrap()).leading_zeros() >= self.bits
    }
}

impl PowStrategy for Sha256PoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        assert!((0.0..64.0).contains(&bits), "bits must be smaller than 64");
        Self { challenge, bits: bits as u32 }
    }

    fn check(&mut self, nonce: u64) -> bool {
        self.check_pow(nonce)
    }

    fn solve(&mut self) -> Option<u64> {
        let this = *self;
        Some(pow_leading_zeros::solve(|nonce| this.check_pow(nonce)))
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
