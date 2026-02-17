use crate::prover::{change_type, change_type_vec, whir_config};
use crate::reference::{ROUND_CONSTANTS, strip_pi};
use crate::sumcheck::util::{self, eq, to_field_vec};
use crate::sumcheck::util::{
    HALF, add_col, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly,
    verify_sumcheck, xor,
};
use crate::transcript::Verifier;
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use tracing::{Level, instrument};
use whir::algebra::fields::Field256;
use whir::algebra::linear_form::{Covector, LinearForm};
use whir::transcript::{Proof as WhirProof, VerifierState};

#[instrument(skip_all)]
pub fn verify(num_vars: usize, output: &[u64], proof: &[Fr], whir_proof: &WhirProof, r: Vec<Fr>) {
    let instances = 1usize << (num_vars - 6);

    let mut verifier = Verifier::new(proof);
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

    // Verify input via commitment
    let span = tracing::span!(Level::INFO, "verify input commitment").entered();

    // Input word reduction (mirrors prover)
    let input_beta = beta;
    let input_alpha = (0..num_vars - 6)
        .map(|_| verifier.generate())
        .collect::<Vec<_>>();

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

    // Build r2 from input reduction
    let mut r2 = Vec::with_capacity(num_vars);
    r2.extend_from_slice(&input_r_x);
    r2.extend_from_slice(&input_r_y);

    // Line restriction verification
    // g(0) = batched evaluation at r (from round claims)
    let g0: Fr = iota
        .iter()
        .enumerate()
        .map(|(i, &v)| input_beta[i] * v)
        .sum();
    // g(1) = batched evaluation at r2 (from input bit sumcheck)
    let g1 = input_b_rx_ry;

    // Read g(2), ..., g(num_vars) from proof
    let mut g_vals = Vec::with_capacity(num_vars + 1);
    g_vals.push(g0);
    g_vals.push(g1);
    for _ in 2..=num_vars {
        g_vals.push(verifier.read());
    }

    // Reconstruct whir config and receive commitment
    let (config, ds) = whir_config(num_vars);
    let mut verifier_state = VerifierState::new_std(&ds, whir_proof);
    let whir_commitment = config.receive_commitment(&mut verifier_state).unwrap();

    // Sample t_star and compute r_star on the line
    let t_star = verifier.generate();
    let r_star: Vec<Fr> = r
        .iter()
        .zip(r2.iter())
        .map(|(a, b)| (Fr::one() - t_star) * a + t_star * b)
        .collect();

    // Read the 25 lane evaluations at r_star
    let r_star_evaluations_fr: Vec<Fr> = (0..25).map(|_| verifier.read()).collect();

    // Check line restriction: g(t_star) == sum_i beta[i] * eval[i]
    let g_t_star = lagrange_interpolate(&g_vals, t_star);
    let batched_eval: Fr = r_star_evaluations_fr
        .iter()
        .enumerate()
        .map(|(i, &e)| input_beta[i] * e)
        .sum();
    assert_eq!(g_t_star, batched_eval);

    // Verify whir opening
    let r_star_f256 = change_type_vec(&r_star);
    let r_star_eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r_star_f256);
    let weight = Covector::new(r_star_eq);
    let r_star_evaluations: Vec<Field256> = r_star_evaluations_fr
        .iter()
        .map(|&e| change_type(e))
        .collect();

    config
        .verify(
            &mut verifier_state,
            &[&whir_commitment],
            &[&weight as &dyn LinearForm<Field256>],
            &r_star_evaluations,
        )
        .unwrap();
    span.exit();
}

/// Lagrange interpolation of a polynomial defined by values at points 0, 1, ..., n
/// evaluated at point t.
fn lagrange_interpolate(values: &[Fr], t: Fr) -> Fr {
    let n = values.len();
    let mut result = Fr::zero();
    for i in 0..n {
        let xi = Fr::from(i as u64);
        let mut basis = Fr::one();
        for j in 0..n {
            if i != j {
                let xj = Fr::from(j as u64);
                basis *= (t - xj) / (xi - xj);
            }
        }
        result += values[i] * basis;
    }
    result
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
