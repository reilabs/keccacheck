use crate::sumcheck::chi::prove_chi;
use crate::sumcheck::iota::prove_iota;
use crate::sumcheck::util::{eval_mle, to_poly};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::Zero;
use crate::reference::{apply_pi, strip_pi};
use crate::sumcheck::rho::prove_rho;

pub fn prove(num_vars: usize, layers: &[Vec<u64>]) -> Vec<Fr> {
    let mut prover = Prover::new();

    // TODO: feed output to the prover before obtaining alpha
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    // write final output sum
    let sum: Fr = layers[0]
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let poly = to_poly(*x);
            beta[i] * eval_mle(&poly, &alpha)
        })
        .sum();

    prover.write(sum);

    // prove iota
    let iota_proof = prove_iota(&mut prover, num_vars, &alpha, &beta, &layers[1], sum);

    // combine subclaims chi_00 and chi_rlc
    let x = prover.read();
    let y = prover.read();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let sum = beta[0] * iota_proof.chi_00 + y * iota_proof.chi_rlc;

    // prove chi
    let pi_chi_proof = prove_chi(&mut prover, num_vars, &iota_proof.r, &beta, &layers[2], sum);

    // reorder pi subclaims
    let mut pi = pi_chi_proof.pi.clone();
    strip_pi(&pi_chi_proof.pi, &mut pi);

    // combine subclaims on pi
    let mut sum = Fr::zero();
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * pi[i];
    });

    // prove rho
    let rho_proof = prove_rho(&mut prover, num_vars, &pi_chi_proof.r, &beta, &layers[3], sum);

    // done
    prover.finish()
}
