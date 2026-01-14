//! Parallel proof-of-work solver for leading-zeros based PoW.

use std::sync::atomic::{AtomicU64, Ordering};

/// Parallel PoW solver using rayon (same pattern as `skyscraper::pow::solve`).
pub fn solve<F>(check: F) -> u64
where
    F: Fn(u64) -> bool + Sync,
{
    let best = AtomicU64::new(u64::MAX);
    rayon::broadcast(|ctx| {
        for nonce in (ctx.index() as u64..).step_by(ctx.num_threads()) {
            if nonce >= best.load(Ordering::Relaxed) {
                return;
            }
            if check(nonce) {
                best.fetch_min(nonce, Ordering::Release);
                return;
            }
        }
    });
    best.load(Ordering::Acquire)
}
