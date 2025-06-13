use crate::reference::{KeccakRoundState, strip_pi};
use crate::sumcheck::chi::prove_chi;
use crate::sumcheck::iota::prove_iota;
use crate::sumcheck::rho::prove_rho;
use crate::sumcheck::theta::prove_theta;
use crate::sumcheck::util::{eval_mle, to_poly};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::{One, Zero};

pub fn prove(num_vars: usize, layers: &KeccakRoundState) -> Vec<Fr> {
    let mut prover = Prover::new();

    // TODO: feed output to the prover before obtaining alpha
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    // write final output sum
    let sum: Fr = layers
        .iota
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let poly = to_poly(*x);
            beta[i] * eval_mle(&poly, &alpha)
        })
        .sum();

    prover.write(sum);

    // prove iota
    let iota_proof = prove_iota(&mut prover, num_vars, &alpha, &beta, &layers.pi_chi, sum);

    // combine subclaims chi_00 and chi_rlc
    let x = prover.read();
    let y = prover.read();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let sum = beta[0] * iota_proof.chi_00 + y * iota_proof.chi_rlc;

    // prove chi
    let pi_chi_proof = prove_chi(
        &mut prover,
        num_vars,
        &iota_proof.r,
        &beta,
        &layers.rho,
        sum,
    );

    // strip pi to get rho
    let mut rho = pi_chi_proof.pi.clone();
    strip_pi(&pi_chi_proof.pi, &mut rho);

    // combine subclaims on rho
    let mut sum = Fr::zero();
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * rho[i];
    });

    // prove rho
    let rho_proof = prove_rho(
        &mut prover,
        num_vars,
        &pi_chi_proof.r,
        &beta,
        &layers.theta,
        sum,
    );

    // combine subclaims on theta, change base
    let theta_xor_base = rho_proof
        .theta
        .iter()
        .map(|x| Fr::one() - x - x)
        .collect::<Vec<_>>();
    let mut sum = Fr::zero();
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_xor_base[i];
    });

    // prove theta
    let theta_proof = prove_theta(
        &mut prover,
        num_vars,
        &rho_proof.r,
        &beta,
        &layers.d,
        &layers.a,
        sum,
    );

    // done
    prover.finish()
}
