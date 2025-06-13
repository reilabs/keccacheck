use crate::reference::{ROUND_CONSTANTS, strip_pi};
use crate::sumcheck::rho::{calculate_evaluations_over_boolean_hypercube_for_rot, derive_rot_evaluations_from_eq};
use crate::sumcheck::util::{add_col, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly, verify_sumcheck, xor, HALF};
use crate::transcript::Verifier;
use ark_bn254::Fr;
use ark_ff::{One, Zero};

pub fn verify(num_vars: usize, output: &[u64], input: &[u64], proof: &[Fr]) {
    let mut verifier = Verifier::new(proof);

    // TODO: feed output to the verifier before obtaining alpha
    let alpha = (0..num_vars)
        .map(|_| verifier.generate())
        .collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    // TODO: we can maybe skip this step and only depend on the sum in the transcript
    // correct sum is required to recover sumcheck polynomials
    let expected_sum = (0..25)
        .map(|i| beta[i] * eval_mle(&to_poly(output[i]), &alpha))
        .sum();
    let sum = verifier.read();
    assert_eq!(sum, expected_sum);

    // verify iota
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let rc = to_poly(ROUND_CONSTANTS[0]);

    let (ve, vrs) = verify_sumcheck::<3>(&mut verifier, num_vars, sum);
    let chi_00 = verifier.read();
    let chi_rlc = verifier.read();

    let e_eq = eval_mle(&eq, &vrs);
    let e_rc = eval_mle(&rc, &vrs);
    assert_eq!(e_eq * (beta[0] * xor(chi_00, e_rc) + chi_rlc), ve);

    // combine subclaims chi_00 and chi_rlc
    let x = verifier.generate();
    let y = verifier.generate();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let expected_sum = beta[0] * chi_00 + y * chi_rlc;

    // verify chi
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&vrs);

    let (ve, vrs) = verify_sumcheck::<4>(&mut verifier, num_vars, expected_sum);
    let pi = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();

    let e_eq = eval_mle(&eq, &vrs);
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
    let rot = (0..25)
        .map(|i| calculate_evaluations_over_boolean_hypercube_for_rot(&vrs, i))
        .collect::<Vec<_>>();

    let (ve, vrs) = verify_sumcheck::<2>(&mut verifier, num_vars, expected_sum);
    let theta = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();

    let e_rot = rot
        .iter()
        .map(|poly| eval_mle(poly, &vrs))
        .collect::<Vec<_>>();
    let checksum = (0..25).map(|i| beta[i] * e_rot[i] * theta[i]).sum::<Fr>();
    assert_eq!(checksum, ve);

    // combine subclaims on theta, change base
    let theta_xor_base = theta
        .iter()
        .map(|x| Fr::one() - x - x)
        .collect::<Vec<_>>();
    let mut expected_sum = Fr::zero();
    // we'll need this beta to combine with the last theta sumcheck!
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * theta_xor_base[i];
    });

    // verify theta
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&vrs);

    let (ve, vrs_theta) = verify_sumcheck::<3>(&mut verifier, num_vars, expected_sum);
    let ai = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let d = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq = eval_mle(&eq, &vrs_theta);
    let mut checksum = Fr::zero();
    for j in 0..5 {
        checksum += e_eq * d[j] * ai[j];
    }
    assert_eq!(checksum, ve);

    // combine subclaims on theta d
    let mut expected_sum = Fr::zero();
    let mut beta_d = vec![Fr::zero(); 5];
    beta_d.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * d[i];
    });

    // verify theta d
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&vrs_theta);

    let (ve, vrs) = verify_sumcheck::<3>(&mut verifier, num_vars, expected_sum);
    let c = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let rot_c = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();

    let e_eq = eval_mle(&eq, &vrs);
    let mut checksum = Fr::zero();
    for j in 0..c.len() {
        checksum += beta_d[j] * e_eq * c[(j + 4) % 5] * rot_c[(j + 1) % 5];
    }
    assert_eq!(ve, checksum);

    // combine subclaims on theta c and rot_c
    let mut expected_sum = Fr::zero();
    let mut beta_c = vec![Fr::zero(); 5];
    let mut beta_rot_c = vec![Fr::zero(); 5];
    beta_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * c[i];
    });
    beta_rot_c.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * rot_c[i];
    });

    // verify theta c
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&vrs);
    let rot = derive_rot_evaluations_from_eq(&eq, 1);

    let (ve, vrs) = verify_sumcheck::<6>(&mut verifier, num_vars, expected_sum);
    let a = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq = eval_mle(&eq, &vrs);
    let e_rot = eval_mle(&rot, &vrs);

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

    ai.iter().enumerate().for_each(|(i, b)| {
        let b = verifier.generate();
        for j in 0..5 {
            beta[j * 5 + i] *= b;
        }
        expected_sum += b * ai[i];
    });
    beta_a.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * a[i];
    });

    // verify theta a
    let eq_ai = calculate_evaluations_over_boolean_hypercube_for_eq(&vrs_theta);
    let eq_a = calculate_evaluations_over_boolean_hypercube_for_eq(&vrs);

    let (ve, vrs) = verify_sumcheck::<2>(&mut verifier, num_vars, expected_sum);
    let mut iota = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq_ai = eval_mle(&eq_ai, &vrs);
    let e_eq_a = eval_mle(&eq_a, &vrs);

    let mut checksum = Fr::zero();
    for j in 0..iota.len() {
        checksum += beta[j] * e_eq_ai * iota[j] + beta_a[j] * e_eq_a * iota[j];
    }
    assert_eq!(ve, checksum);

    // change iota base
    iota.iter_mut().for_each(|i| *i = HALF * (Fr::one() - *i));

    // for a single round keccak, this was the last step. make sure inputs match
    for i in 0..25 {
        assert_eq!(eval_mle(&to_poly(input[i]), &vrs), iota[i]);
    }
}
