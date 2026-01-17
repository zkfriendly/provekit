//! Dummy proof of work for benchmarking - NOT SECURE, just fast.
//! Always succeeds with nonce 0.

use spongefish_pow::PowStrategy;

/// Dummy proof of work that always succeeds immediately.
/// WARNING: This is NOT cryptographically secure!
#[derive(Clone, Copy)]
pub struct DummyPoW {
    _challenge: [u8; 32],
    _bits:      f64,
}

impl PowStrategy for DummyPoW {
    fn new(challenge: [u8; 32], bits: f64) -> Self {
        Self {
            _challenge: challenge,
            _bits:      bits,
        }
    }

    #[inline(always)]
    fn check(&mut self, _nonce: u64) -> bool {
        // Always succeeds - NOT SECURE!
        true
    }

    #[inline(always)]
    fn solve(&mut self) -> Option<u64> {
        // Always return 0 immediately
        Some(0)
    }
}

#[test]
fn test_pow_dummy() {
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
    prover.challenge_pow::<DummyPoW>(BITS).unwrap();

    let mut verifier = iopattern.to_verifier_state(prover.narg_string());
    let byte = verifier.next_bytes::<1>().unwrap();
    assert_eq!(&byte, b"\0");
    verifier.challenge_pow::<DummyPoW>(BITS).unwrap();
}
