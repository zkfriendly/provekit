use {
    ark_bn254::Fr,
    ark_ff::BigInt,
    bn254_multiplier::{constants::OUTPUT_MAX, scalar_mul},
    divan::Bencher,
    primitive_types::U256,
    rand::{rng, Rng},
};

struct MulInputs {
    raw_a: [u64; 4],
    raw_b: [u64; 4],
    ark_a: Fr,
    ark_b: Fr,
}

fn sample_safe_montgomery_input(rng: &mut impl Rng) -> [u64; 4] {
    let max = U256(OUTPUT_MAX);

    loop {
        let candidate: [u64; 4] = rng.random();
        if U256(candidate) <= max {
            return candidate;
        }
    }
}

fn sample_mul_inputs() -> MulInputs {
    let mut rng = rng();
    let raw_a = sample_safe_montgomery_input(&mut rng);
    let raw_b = sample_safe_montgomery_input(&mut rng);

    MulInputs {
        raw_a,
        raw_b,
        ark_a: Fr::new(BigInt(raw_a)),
        ark_b: Fr::new(BigInt(raw_b)),
    }
}

#[divan::bench]
fn skyscraper_bn254_mul(bencher: Bencher) {
    bencher
        .with_inputs(sample_mul_inputs)
        .bench_local_values(|inputs| scalar_mul(inputs.raw_a, inputs.raw_b));
}

#[divan::bench]
fn arkworks_bn254_mul(bencher: Bencher) {
    bencher
        .with_inputs(sample_mul_inputs)
        .bench_local_values(|inputs| inputs.ark_a * inputs.ark_b);
}

fn main() {
    divan::main();
}
