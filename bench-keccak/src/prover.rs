use crate::reference::{KeccakRoundState, strip_pi_t};
use crate::sumcheck::chi::prove_chi;
use crate::sumcheck::iota::prove_iota;
use crate::sumcheck::rho::prove_rho;
use crate::sumcheck::theta::prove_theta;
use crate::sumcheck::theta_a::prove_theta_a;
use crate::sumcheck::theta_c::prove_theta_c;
use crate::sumcheck::theta_d::prove_theta_d;
use crate::sumcheck::util::{eval_mle, to_poly_multi};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use tracing::instrument;

#[instrument(skip(layers))]
pub fn prove(num_vars: usize, layers: &KeccakRoundState) -> Vec<Fr> {
    let instances = 1usize << (num_vars - 6);

    let mut prover = Prover::new();

    // TODO: feed output to the prover before obtaining alpha
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    // write final output sum
    let sum: Fr = layers
        .iota
        .chunks_exact(instances)
        .enumerate()
        .map(|(i, x)| {
            let poly = to_poly_multi(x);
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
    strip_pi_t(&pi_chi_proof.pi, &mut rho);

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
    // we need that beta to combine with the last theta sumcheck!
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

    // combine subclaims on theta d
    let mut sum = Fr::zero();
    let mut beta_d = vec![Fr::zero(); theta_proof.d.len()];
    beta_d.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_proof.d[i];
    });

    // prove theta d
    let theta_d_proof = prove_theta_d(
        &mut prover,
        num_vars,
        &theta_proof.r,
        &beta_d,
        &layers.c,
        sum,
    );

    // combine claims on theta c and rot_c
    let mut sum = Fr::zero();
    let mut beta_c = vec![Fr::zero(); theta_d_proof.c.len()];
    let mut beta_rot_c = vec![Fr::zero(); theta_d_proof.rot_c.len()];
    beta_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_d_proof.c[i];
    });
    beta_rot_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_d_proof.rot_c[i];
    });

    // prove theta c
    let theta_c_proof = prove_theta_c(
        &mut prover,
        num_vars,
        &theta_d_proof.r,
        &beta_c,
        &beta_rot_c,
        &layers.a,
        sum,
    );

    // combine claims on a from theta and theta c
    let mut sum = Fr::zero();
    let mut beta_a = vec![Fr::zero(); theta_c_proof.a.len()];

    theta_proof.ai.iter().enumerate().for_each(|(i, b)| {
        let b = prover.read();
        for j in 0..5 {
            beta[j * 5 + i] *= b;
        }
        sum += b * theta_proof.ai[i];
    });
    beta_a.iter_mut().enumerate().for_each(|(i, b)| {
        *b = prover.read();
        sum += *b * theta_c_proof.a[i];
    });

    // prove theta a
    let theta_a_proof = prove_theta_a(
        &mut prover,
        num_vars,
        &theta_proof.r,
        &theta_c_proof.r,
        &beta,
        &beta_a,
        &layers.a,
        sum,
    );

    // done
    prover.finish()
}
