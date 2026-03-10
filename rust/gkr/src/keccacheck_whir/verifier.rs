#[cfg(debug_assertions)]
use super::protocol_utils::deserialize_whir_proof;
#[cfg(not(debug_assertions))]
use super::protocol_utils::deserialize_whir_proof_flat;
use super::protocol_utils::{change_type, change_type_vec, whir_config};
use crate::poseidon::COUNT_16;
use crate::reference::{ROUND_CONSTANTS, strip_pi};
use crate::sumcheck::binary::verify_binary;
use crate::sumcheck::util::{self, eq, to_field_vec};
use crate::sumcheck::util::{
    HALF, add_col, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly,
    verify_sumcheck, xor,
};

use crate::transcript::{Sponge, Verifier};
use ark_bn254::Fr;
use ark_ff::{One, PrimeField, Zero};
use tracing::{Level, instrument};
use whir::algebra::fields::Field256;
use whir::algebra::linear_form::{Covector, LinearForm};
use whir::transcript::VerifierState;

#[instrument(skip_all)]
pub fn verify(num_vars: usize, output: &[u64], proof: &[Fr], whir_proof: Vec<u8>, r: Vec<Fr>) {
    COUNT_16.store(0, std::sync::atomic::Ordering::SeqCst);
    let instances = 1usize << (num_vars - 6);

    // Extract and verify WHIR proof
    #[cfg(debug_assertions)]
    let deser_whir_proof = deserialize_whir_proof(&whir_proof);
    #[cfg(not(debug_assertions))]
    let deser_whir_proof = deserialize_whir_proof_flat(&whir_proof);
    let (config, ds) = whir_config(num_vars);
    let mut verifier_state = VerifierState::new(&ds, &deser_whir_proof, Sponge::new());
    let whir_commitment = config.receive_commitment(&mut verifier_state).unwrap();

    let mut verifier = Verifier::new(proof);
    let root = whir_commitment.root();
    verifier.absorb(Fr::from_le_bytes_mod_order(&root.0));
    let span = tracing::span!(Level::INFO, "calculate output sum").entered();
    r.iter().for_each(|challenge| verifier.absorb(*challenge));
    let mut beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    let expected_sum = (0..25)
        .map(|i| {
            beta[i]
                * eval_mle(
                    &to_field_vec(&output[(i * instances)..(i * instances + instances)]),
                    &r,
                )
        })
        .sum();
    let mut sum = verifier.read();
    assert_eq!(sum, expected_sum);
    span.exit();

    // Verify the bitwise decomposition of the output words
    let span = tracing::span!(Level::INFO, "Reduction of output words").entered();

    let (c_1, r_x) = verify_sumcheck::<2>(&mut verifier, num_vars - 6, sum);

    let words_r_x = verifier.read();
    let eq_alpha_rx = eq(&r, &r_x);
    assert_eq!(c_1, words_r_x * eq_alpha_rx);

    let (c_2, r_y) = verify_sumcheck::<2>(&mut verifier, 6, words_r_x);
    let b_r_x_r_y = verifier.read();
    let powers: Vec<Fr> = (0..1 << 6).map(|i| Fr::from(1u64 << i)).collect();

    let powers_eval = eval_mle(&powers, &r_y);

    assert_eq!(c_2, powers_eval * b_r_x_r_y);
    span.exit();

    sum = b_r_x_r_y;
    let span = tracing::span!(Level::INFO, "verify all rounds").entered();
    let mut iota = Vec::new();

    // create the main keccacheck round challenge
    let mut r = Vec::with_capacity(num_vars);
    r.extend(r_x);
    r.extend(r_y);

    for round in (0..24).rev() {
        (r, iota) = verify_round(
            &mut verifier,
            num_vars,
            &r,
            &mut beta,
            sum,
            ROUND_CONSTANTS[round],
        );
        if round != 0 {
            sum = Fr::zero();
            beta.iter_mut().enumerate().for_each(|(i, b)| {
                *b = verifier.generate();
                sum += *b * iota[i];
            });
        }
    }
    span.exit();

    // Verify input bits via commitment

    let output_beta = beta;
    let output_r = r;

    // Binary claim verification
    let binary_beta: Vec<Fr> = (0..25).map(|_| verifier.generate()).collect();
    let binary_alpha: Vec<Fr> = (0..num_vars).map(|_| verifier.generate()).collect();
    let binary_proof = verify_binary(&mut verifier, num_vars, &binary_alpha, &binary_beta, 25);
    let binary_r = binary_proof.r_x;

    // Input word reduction (fresh betas)
    let input_beta: Vec<Fr> = (0..25).map(|_| verifier.generate()).collect();
    let input_alpha: Vec<Fr> = (0..num_vars - 6).map(|_| verifier.generate()).collect();

    let input_c = verifier.read();

    // Verify word-level sumcheck
    let (ic_1, input_r_x) = verify_sumcheck::<2>(&mut verifier, num_vars - 6, input_c);
    let input_words_rx = verifier.read();
    let input_eq = eq(&input_alpha, &input_r_x);
    assert_eq!(ic_1, input_words_rx * input_eq);

    // Verify bit-level sumcheck
    let (ic_2, input_r_y) = verify_sumcheck::<2>(&mut verifier, 6, input_words_rx);
    let input_b_rx_ry = verifier.read();
    let input_powers_eval = eval_mle(&powers, &input_r_y);
    assert_eq!(ic_2, input_powers_eval * input_b_rx_ry);

    let mut input_r = Vec::with_capacity(num_vars);
    input_r.extend_from_slice(&input_r_x);
    input_r.extend_from_slice(&input_r_y);

    // Read 75 individual lane evaluations (25 lanes × 3 claim points)
    let lane_evals: Vec<[Fr; 3]> = (0..25)
        .map(|_| [verifier.read(), verifier.read(), verifier.read()])
        .collect();

    // Check round claim: sum_k output_beta[k] * lane_k(output_r) == sum_k output_beta[k] * iota[k]
    let round_claim: Fr = (0..25).map(|k| output_beta[k] * lane_evals[k][0]).sum();
    let expected_round: Fr = (0..25).map(|k| output_beta[k] * iota[k]).sum();
    assert_eq!(round_claim, expected_round);

    // Check binary claim: sum_k binary_beta[k] * lane_k(binary_r) matches binary sumcheck
    let binary_claim: Fr = (0..25).map(|k| binary_beta[k] * lane_evals[k][1]).sum();
    assert_eq!(binary_claim, binary_proof.batched_eval);

    // Check input claim: sum_k input_beta[k] * lane_k(input_r) == input_b_rx_ry
    let input_claim: Fr = (0..25).map(|k| input_beta[k] * lane_evals[k][2]).sum();
    assert_eq!(input_claim, input_b_rx_ry);

    // Sample gamma and build combined linear form
    let gamma = verifier.generate();
    let gamma2 = gamma * gamma;

    let eq1 = calculate_evaluations_over_boolean_hypercube_for_eq(&output_r);
    let eq2 = calculate_evaluations_over_boolean_hypercube_for_eq(&binary_r);
    let eq3 = calculate_evaluations_over_boolean_hypercube_for_eq(&input_r);

    let combined_eq: Vec<Fr> = eq1
        .iter()
        .zip(eq2.iter())
        .zip(eq3.iter())
        .map(|((e1, e2), e3)| *e1 + gamma * *e2 + gamma2 * *e3)
        .collect();
    let combined_cov = Covector::new(change_type_vec(&combined_eq));

    // 25 combined evaluations: lane_k(r1) + γ·lane_k(r2) + γ²·lane_k(r3)
    let evaluations: Vec<Field256> = lane_evals
        .iter()
        .map(|[e1, e2, e3]| change_type(*e1 + gamma * *e2 + gamma2 * *e3))
        .collect();

    let span = tracing::span!(Level::INFO, "verify whir").entered();
    config
        .verify(
            &mut verifier_state,
            &[&whir_commitment],
            &[&combined_cov as &dyn LinearForm<Field256>],
            &evaluations,
        )
        .unwrap();
    println!("verifier permutations {:?}", COUNT_16);
    span.exit();
}

fn verify_round(
    verifier: &mut Verifier,
    num_vars: usize,
    alpha: &[Fr],
    beta: &mut [Fr],
    sum: Fr,
    rc: u64,
) -> (Vec<Fr>, Vec<Fr>) {
    // verify iota
    let (ve, vrs_iota) = verify_sumcheck::<3>(verifier, num_vars, sum);
    let chi_00 = verifier.read();
    let chi_rlc = verifier.read();

    let e_eq = util::eq(alpha, &vrs_iota);
    let rc = to_poly(&[rc; 1]);
    let e_rc = eval_mle(&rc, &vrs_iota[(vrs_iota.len() - 6)..]);
    assert_eq!(e_eq * (beta[0] * xor(chi_00, e_rc) + chi_rlc), ve);

    // combine subclaims chi_00 and chi_rlc
    let x = verifier.generate();
    let y = verifier.generate();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let expected_sum = beta[0] * chi_00 + y * chi_rlc;

    // verify chi
    let (ve, vrs_chi) = verify_sumcheck::<4>(verifier, num_vars, expected_sum);
    let pi = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();

    let e_eq = util::eq(&vrs_iota, &vrs_chi);
    let mut checksum_pi = Fr::zero();
    for i in 0..pi.len() {
        checksum_pi +=
            e_eq * beta[i] * xor(pi[i], (Fr::one() - pi[add_col(i, 1)]) * (pi[add_col(i, 2)]));
    }
    assert_eq!(checksum_pi, ve);

    // strip pi to get rho
    let mut rho = pi.clone();
    strip_pi(&pi, &mut rho);

    // combine subclaims on rho
    let mut expected_sum = Fr::zero();
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * rho[i];
    });

    // verify rho
    let (ve, vrs_rho) = verify_sumcheck::<2>(verifier, num_vars, expected_sum);
    let theta = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_rot = (0..25)
        .map(|i| util::rot(i, &vrs_chi, &vrs_rho))
        .collect::<Vec<_>>();
    let checksum = (0..25).map(|i| beta[i] * e_rot[i] * theta[i]).sum::<Fr>();
    assert_eq!(checksum, ve);

    // combine subclaims on theta, change base
    let theta_xor_base = theta.iter().map(|x| Fr::one() - x - x).collect::<Vec<_>>();
    let mut expected_sum = Fr::zero();
    // we'll need this beta to combine with the last theta sumcheck!
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * theta_xor_base[i];
    });

    // verify theta
    let (ve, vrs_theta) = verify_sumcheck::<3>(verifier, num_vars, expected_sum);
    let ai = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let d = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq = util::eq(&vrs_rho, &vrs_theta);
    let mut checksum = Fr::zero();
    for j in 0..5 {
        checksum += e_eq * d[j] * ai[j];
    }
    assert_eq!(checksum, ve);

    // combine subclaims on theta d
    let mut expected_sum = Fr::zero();
    let mut beta_d = [Fr::zero(); 5];
    beta_d.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * d[i];
    });

    // verify theta d
    let (ve, vrs_d) = verify_sumcheck::<3>(verifier, num_vars, expected_sum);
    let c = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let rot_c = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();

    let e_eq = util::eq(&vrs_theta, &vrs_d);
    let mut checksum = Fr::zero();
    for j in 0..c.len() {
        checksum += beta_d[j] * e_eq * c[(j + 4) % 5] * rot_c[(j + 1) % 5];
    }
    assert_eq!(ve, checksum);

    // combine subclaims on theta c and rot_c
    let mut expected_sum = Fr::zero();
    let mut beta_c = [Fr::zero(); 5];
    let mut beta_rot_c = [Fr::zero(); 5];
    beta_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * c[i];
    });
    beta_rot_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * rot_c[i];
    });

    // verify theta c
    let (ve, vrs_c) = verify_sumcheck::<6>(verifier, num_vars, expected_sum);
    let a = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq = util::eq(&vrs_d, &vrs_c);
    let e_rot = util::rot(1, &vrs_d, &vrs_c);

    let mut checksum = Fr::zero();
    for j in 0..5 {
        let mut product = Fr::one();
        for i in 0..5 {
            product *= a[i * 5 + j];
        }
        checksum += beta_c[j] * e_eq * product;
        checksum += beta_rot_c[j] * e_rot * product;
    }
    assert_eq!(ve, checksum);

    // combine claims on a from theta and theta c
    let mut expected_sum = Fr::zero();
    let mut beta_a = vec![Fr::zero(); a.len()];

    ai.iter().enumerate().for_each(|(i, a)| {
        let b = verifier.generate();
        for j in 0..5 {
            beta[j * 5 + i] *= b;
        }
        expected_sum += b * *a;
    });
    beta_a.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * a[i];
    });

    // verify theta a
    let (ve, vrs_a) = verify_sumcheck::<2>(verifier, num_vars, expected_sum);
    let mut iota = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq_ai = util::eq(&vrs_theta, &vrs_a);
    let e_eq_a = util::eq(&vrs_c, &vrs_a);

    let mut checksum = Fr::zero();
    for j in 0..iota.len() {
        checksum += beta[j] * e_eq_ai * iota[j] + beta_a[j] * e_eq_a * iota[j];
    }
    assert_eq!(ve, checksum);

    // change iota base
    iota.iter_mut().for_each(|i| *i = HALF * (Fr::one() - *i));

    (vrs_a, iota)
}
