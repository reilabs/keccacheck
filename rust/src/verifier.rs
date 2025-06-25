use crate::reference::{ROUND_CONSTANTS, strip_pi};
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
    let span = tracing::span!(Level::INFO, "calculate output sum").entered();
    let mut r = (0..num_vars)
        .map(|_| verifier.generate())
        .collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    let expected_sum = (0..25)
        .map(|i| {
            beta[i]
                * eval_mle(
                    &to_poly(&output[(i * instances)..(i * instances + instances)]),
                    &r,
                )
        })
        .sum();
    let mut sum = verifier.read();
    assert_eq!(sum, expected_sum);
    span.exit();

    let span = tracing::span!(Level::INFO, "verify all rounds").entered();
    let mut iota = Vec::new();
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

    // verify input
    let span = tracing::span!(Level::INFO, "evaluate input at random point").entered();
    for i in 0..25 {
        assert_eq!(
            eval_mle(
                &to_poly(&input[(i * instances)..(i * instances + instances)]),
                &r
            ),
            iota[i]
        );
    }
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
    let instances = 1usize << (num_vars - 6);

    // verify iota
    // TODO: no need to materialize this polynomial
    let rc = to_poly(&vec![rc; instances]);

    let (ve, vrs_iota) = verify_sumcheck::<3>(verifier, num_vars, sum);
    let chi_00 = verifier.read();
    let chi_rlc = verifier.read();

    let e_eq = util::eq(alpha, &vrs_iota);
    let e_rc = eval_mle(&rc, &vrs_iota);
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
