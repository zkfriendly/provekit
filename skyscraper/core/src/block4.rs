use {
    crate::generic,
    core::array,
    fp_rounding::{with_rounding_mode, RoundingGuard, Zero},
};

pub fn compress_many(messages: &[u8], hashes: &mut [u8]) {
    unsafe {
        with_rounding_mode((messages, hashes), move |guard, (messages, hashes)| {
            generic::compress_many(|input| compress(guard, input), messages, hashes)
        });
    }
}

/// Reduce 4 chains of `[u64; 4]` values in parallel using block4 compression.
///
/// Each chain is reduced left-to-right: `compress(compress(compress(a, b), c), d)`.
/// All 4 chains are processed simultaneously at each step, exploiting the
/// interleaved scalar + NEON SIMD squaring in block4.
///
/// The FPCR rounding mode is set once and amortized over all steps.
pub fn compress_reduce_4(chains: [&[[u64; 4]]; 4]) -> [[u64; 4]; 4] {
    let len = chains[0].len();
    assert!(len >= 2, "chains must have at least 2 elements");
    debug_assert!(chains.iter().all(|c| c.len() == len), "all chains must be the same length");

    unsafe {
        with_rounding_mode((), move |guard, ()| {
            // Initialize accumulators by compressing first two elements
            let mut acc = compress(
                guard,
                [
                    [chains[0][0], chains[0][1]],
                    [chains[1][0], chains[1][1]],
                    [chains[2][0], chains[2][1]],
                    [chains[3][0], chains[3][1]],
                ],
            );

            // Fold in remaining elements
            for j in 2..len {
                acc = compress(
                    guard,
                    [
                        [acc[0], chains[0][j]],
                        [acc[1], chains[1][j]],
                        [acc[2], chains[2][j]],
                        [acc[3], chains[3][j]],
                    ],
                );
            }

            acc
        })
    }
}

#[inline(always)]
fn compress(guard: &RoundingGuard<Zero>, input: [[[u64; 4]; 2]; 4]) -> [[u64; 4]; 4] {
    generic::compress(|x| square(guard, x), input)
}

#[inline(always)]
fn square(guard: &RoundingGuard<Zero>, n: [[u64; 4]; 4]) -> [[u64; 4]; 4] {
    let [a, b, c, d] = n;
    let v = array::from_fn(|i| std::simd::u64x2::from_array([c[i], d[i]]));
    let (a, b, v) = bn254_multiplier::montgomery_square_log_interleaved_4(guard, a, b, v);
    let c = v.map(|e| e[0]);
    let d = v.map(|e| e[1]);
    [a, b, c, d]
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        proptest::{
            collection::vec,
            prelude::{any, Strategy},
            proptest,
        },
    };

    fn random_input() -> impl Strategy<Value = Vec<u8>> {
        (1usize..=10).prop_flat_map(|chunks| vec(any::<u8>(), chunks * 64))
    }

    #[test]
    fn test_eq_ref() {
        proptest!(|(input in random_input())| {
            let mut r = vec![0; input.len() / 2];
            let mut e = vec![0; input.len() / 2];
            crate::reference::compress_many(&input, &mut e);
            compress_many(&input, &mut r);
            assert_eq!(r, e);
        });
    }
}
