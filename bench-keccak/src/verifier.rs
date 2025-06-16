use crate::reference::{ROUND_CONSTANTS, strip_pi_t};
use crate::sumcheck::util;
use crate::sumcheck::util::{HALF, add_col, eval_mle, to_poly, verify_sumcheck, xor};
use crate::transcript::Verifier;
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use tracing::{Level, instrument};

#[instrument(skip_all)]
pub fn verify(num_vars: usize, output: &[u64], input: &[u64], proof: &[Fr]) {
    let instances = 1usize << (num_vars - 6);

    let mut verifier = Verifier::new(proof);

    // TODO: feed output to the verifier before obtaining alpha
    let span = tracing::span!(Level::INFO, "obtain_sum").entered();
    let alpha = (0..num_vars)
        .map(|_| verifier.generate())
        .collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    let expected_sum = (0..25)
        .map(|i| {
            beta[i]
                * eval_mle(
                    &to_poly(&output[(i * instances)..(i * instances + instances)]),
                    &alpha,
                )
        })
        .sum();
    let sum = verifier.read();
    assert_eq!(sum, expected_sum);
    span.exit();

    // verify iota
    let span = tracing::span!(Level::INFO, "verify_iota").entered();
    // TODO: no need to materialize this polynomial
    let rc = to_poly(&vec![ROUND_CONSTANTS[0]; instances]);

    let (ve, vrs_iota) = verify_sumcheck::<3>(&mut verifier, num_vars, sum);
    let chi_00 = verifier.read();
    let chi_rlc = verifier.read();

    let e_eq = util::eq(&alpha, &vrs_iota);
    let e_rc = eval_mle(&rc, &vrs_iota);
    assert_eq!(e_eq * (beta[0] * xor(chi_00, e_rc) + chi_rlc), ve);
    span.exit();

    // combine subclaims chi_00 and chi_rlc
    let span = tracing::span!(Level::INFO, "combine_chi").entered();
    let x = verifier.generate();
    let y = verifier.generate();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let expected_sum = beta[0] * chi_00 + y * chi_rlc;
    span.exit();

    // verify chi
    let span = tracing::span!(Level::INFO, "verify_chi").entered();
    let (ve, vrs_chi) = verify_sumcheck::<4>(&mut verifier, num_vars, expected_sum);
    let pi = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();

    let e_eq = util::eq(&vrs_iota, &vrs_chi);
    let mut checksum_pi = Fr::zero();
    for i in 0..pi.len() {
        checksum_pi +=
            e_eq * beta[i] * xor(pi[i], (Fr::one() - pi[add_col(i, 1)]) * (pi[add_col(i, 2)]));
    }
    assert_eq!(checksum_pi, ve);
    span.exit();

    // strip pi to get rho
    let span = tracing::span!(Level::INFO, "strip_pi").entered();
    let mut rho = pi.clone();
    strip_pi_t(&pi, &mut rho);
    span.exit();

    // combine subclaims on rho
    let span = tracing::span!(Level::INFO, "combine_rho").entered();
    let mut expected_sum = Fr::zero();
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * rho[i];
    });
    span.exit();

    // verify rho
    let span = tracing::span!(Level::INFO, "verify_rho").entered();
    let (ve, vrs_rho) = verify_sumcheck::<2>(&mut verifier, num_vars, expected_sum);
    let theta = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_rot = (0..25)
        .map(|i| util::rot(i, &vrs_chi, &vrs_rho))
        .collect::<Vec<_>>();
    let checksum = (0..25).map(|i| beta[i] * e_rot[i] * theta[i]).sum::<Fr>();
    assert_eq!(checksum, ve);
    span.exit();

    // combine subclaims on theta, change base
    let span = tracing::span!(Level::INFO, "combine_theta").entered();
    let theta_xor_base = theta.iter().map(|x| Fr::one() - x - x).collect::<Vec<_>>();
    let mut expected_sum = Fr::zero();
    // we'll need this beta to combine with the last theta sumcheck!
    beta.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * theta_xor_base[i];
    });
    span.exit();

    // verify theta
    let span = tracing::span!(Level::INFO, "verify_theta").entered();
    let (ve, vrs_theta) = verify_sumcheck::<3>(&mut verifier, num_vars, expected_sum);
    let ai = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let d = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq = util::eq(&vrs_rho, &vrs_theta);
    let mut checksum = Fr::zero();
    for j in 0..5 {
        checksum += e_eq * d[j] * ai[j];
    }
    assert_eq!(checksum, ve);
    span.exit();

    // combine subclaims on theta d
    let span = tracing::span!(Level::INFO, "combine_theta_d").entered();
    let mut expected_sum = Fr::zero();
    let mut beta_d = [Fr::zero(); 5];
    beta_d.iter_mut().enumerate().for_each(|(i, b)| {
        *b = verifier.generate();
        expected_sum += *b * d[i];
    });
    span.exit();

    // verify theta d
    let span = tracing::span!(Level::INFO, "verify_theta_d").entered();
    let (ve, vrs_d) = verify_sumcheck::<3>(&mut verifier, num_vars, expected_sum);
    let c = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();
    let rot_c = (0..5).map(|_| verifier.read()).collect::<Vec<_>>();

    let e_eq = util::eq(&vrs_theta, &vrs_d);
    let mut checksum = Fr::zero();
    for j in 0..c.len() {
        checksum += beta_d[j] * e_eq * c[(j + 4) % 5] * rot_c[(j + 1) % 5];
    }
    assert_eq!(ve, checksum);
    span.exit();

    // combine subclaims on theta c and rot_c
    let span = tracing::span!(Level::INFO, "combine_theta_rot_c").entered();
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
    span.exit();

    // verify theta c
    let span = tracing::span!(Level::INFO, "verify_theta_c").entered();
    let (ve, vrs_c) = verify_sumcheck::<6>(&mut verifier, num_vars, expected_sum);
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
    span.exit();

    // combine claims on a from theta and theta c
    let span = tracing::span!(Level::INFO, "combine_theta_c").entered();
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
    span.exit();

    // verify theta a
    let span = tracing::span!(Level::INFO, "verify_theta_a").entered();
    let (ve, vrs_a) = verify_sumcheck::<2>(&mut verifier, num_vars, expected_sum);
    let mut iota = (0..25).map(|_| verifier.read()).collect::<Vec<_>>();
    let e_eq_ai = util::eq(&vrs_theta, &vrs_a);
    let e_eq_a = util::eq(&vrs_c, &vrs_a);

    let mut checksum = Fr::zero();
    for j in 0..iota.len() {
        checksum += beta[j] * e_eq_ai * iota[j] + beta_a[j] * e_eq_a * iota[j];
    }
    assert_eq!(ve, checksum);
    span.exit();

    let span = tracing::span!(Level::INFO, "verify_input").entered();
    // change iota base
    iota.iter_mut().for_each(|i| *i = HALF * (Fr::one() - *i));

    // for a single round keccak, this was the last step. make sure inputs match
    for i in 0..25 {
        assert_eq!(
            eval_mle(
                &to_poly(&input[(i * instances)..(i * instances + instances)]),
                &vrs_a
            ),
            iota[i]
        );
    }
    span.exit();
}
