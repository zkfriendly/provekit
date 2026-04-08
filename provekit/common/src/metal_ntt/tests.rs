use {
    super::MetalBn254Ntt,
    ark_bn254::Fr,
    ark_ff::UniformRand,
    whir::{
        algebra::{
            embedding::Identity,
            ntt::{ArkNtt, ReedSolomon},
        },
        hash::SHA2,
        protocols::irs_commit::AcceleratedCommitter,
        transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
    },
};

#[test]
fn metal_matches_cpu_for_small_case() {
    let gpu = MetalBn254Ntt::new().unwrap();
    eprintln!(
        "using Metal device: {}",
        gpu.runtime().unwrap().device.name()
    );

    let mut rng = ark_std::test_rng();
    let coeffs: Vec<_> = (0..(1 << 12)).map(|_| Fr::rand(&mut rng)).collect();
    let cpu = ArkNtt::<Fr>::default().interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
    let gpu = gpu.interleaved_encode(&[&coeffs], 1 << 11, 1 << 1);
    assert_eq!(cpu, gpu);
}

#[test]
fn metal_matches_cpu_for_small_codeword_case() {
    let gpu = MetalBn254Ntt::new().unwrap();
    let mut rng = ark_std::test_rng();
    let coeffs: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
    let cpu = ArkNtt::<Fr>::default().interleaved_encode(&[&coeffs], 32, 2);
    let gpu = gpu.gpu_encode(&[&coeffs], 32, 2).unwrap();
    assert_eq!(cpu, gpu);
}

#[test]
fn metal_field_mul_matches_cpu() {
    let gpu = MetalBn254Ntt::new().unwrap();
    let mut rng = ark_std::test_rng();
    let lhs: Vec<_> = (0..4096).map(|_| Fr::rand(&mut rng)).collect();
    let rhs: Vec<_> = (0..4096).map(|_| Fr::rand(&mut rng)).collect();
    let expected: Vec<_> = lhs.iter().zip(&rhs).map(|(&a, &b)| a * b).collect();
    let actual = gpu.gpu_mul_pairs(&lhs, &rhs).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn metal_matches_cpu_for_multi_poly_case() {
    let gpu = MetalBn254Ntt::new().unwrap();
    let mut rng = ark_std::test_rng();
    let coeffs_a: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
    let coeffs_b: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
    let coeffs = [&coeffs_a[..], &coeffs_b[..]];
    let cpu = ArkNtt::<Fr>::default().interleaved_encode(&coeffs, 32, 2);
    let gpu = gpu.gpu_encode(&coeffs, 32, 2).unwrap();
    assert_eq!(cpu, gpu);
}

#[test]
fn metal_small_commit_uses_gpu() {
    let gpu = MetalBn254Ntt::new().unwrap();
    let mut rng = ark_std::test_rng();
    let coeffs_a: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
    let coeffs_b: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();
    let coeffs = [&coeffs_a[..], &coeffs_b[..]];
    let codeword_length = 32usize;
    let interleaving_depth = 2usize;
    let matrix_commit =
        whir::protocols::matrix_commit::Config::<Fr>::with_hash(SHA2, codeword_length, 4);

    let accelerated = gpu
        .try_commit_interleaved(&coeffs, &matrix_commit, interleaving_depth)
        .unwrap()
        .is_some();
    assert!(accelerated);
}

#[test]
fn irs_commit_roundtrip_small_case_uses_accelerated_matrix() {
    crate::register_ntt();

    let config =
        whir::protocols::irs_commit::Config::<Identity<Fr>>::new(20.0, true, SHA2, 1, 32, 2, 0.5);
    let ds = DomainSeparator::protocol(&config)
        .session(&format!("Test at {}:{}", file!(), line!()))
        .instance(&Empty);

    let mut rng = ark_std::test_rng();
    let vector: Vec<_> = (0..32).map(|_| Fr::rand(&mut rng)).collect();

    let mut prover_state = ProverState::new_std(&ds);
    let witness = config.commit(&mut prover_state, &[vector.as_slice()]);
    assert!(witness.uses_accelerated_matrix());
    let evals = config.open(&mut prover_state, &[&witness]);
    let proof = prover_state.proof();

    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let commitment = config.receive_commitment(&mut verifier_state).unwrap();
    let verified = config.verify(&mut verifier_state, &[&commitment]).unwrap();
    assert_eq!(verified, evals);
    verifier_state.check_eof().unwrap();
}
