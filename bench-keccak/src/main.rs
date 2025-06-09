use std::str::FromStr;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, One, Zero};
use itertools::izip;

use crate::sumcheck::chi::prove_sumcheck_chi;
use crate::sumcheck::util::add_col;
use crate::{
    reference::{ROUND_CONSTANTS, keccak_round},
    sumcheck::{
        iota::prove_sumcheck_iota,
        util::{
            calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly,
            verify_sumcheck, xor,
        },
    },
    transcript::{Prover, Verifier},
};

mod poseidon;
mod reference;
mod sumcheck;
mod transcript;

#[test]
fn iota_no_recursion() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input.clone();
    let output = keccak_round(&mut buf, ROUND_CONSTANTS[0]);
    // output:
    // [0] - iota
    // [1] - chi
    // [2] - pi

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let chi_00 = to_poly(output[1][0]);
    let rc = to_poly(ROUND_CONSTANTS[0]);
    let mut chi_rlc = vec![Fr::ZERO; 1 << num_vars];
    for el in 1..25 {
        // iterating from 1 to skip the first state element (i, j) = (0, 0)
        let poly = to_poly(output[1][el]);
        for x in 0..(1 << num_vars) {
            chi_rlc[x] += beta[el] * poly[x];
        }
    }
    let chi = output[1].iter().map(|x| to_poly(*x)).collect::<Vec<_>>();
    let iota = output[0].iter().map(|x| to_poly(*x)).collect::<Vec<_>>();

    let real_iota_sum: Fr = iota
        .iter()
        .enumerate()
        .map(|(i, poly)| {
            beta[i] * eval_mle(&poly, &alpha)
        })
        .sum();

    let (pe, prs, _) = {
        let mut eq = eq.clone();
        let mut chi_00 = chi_00.clone();
        let mut rc = rc.clone();
        let mut chi_rlc = chi_rlc.clone();
        prove_sumcheck_iota(
            &mut prover,
            num_vars,
            beta[0],
            &mut eq,
            &mut chi_00,
            &mut rc,
            &mut chi_rlc,
            real_iota_sum,
        )
    };
    let e_eq = eval_mle(&eq, &prs); // TODO: can evaluate eq faster
    let e_chi_00 = eval_mle(&chi_00, &prs);
    let e_rc = eval_mle(&rc, &prs);
    let e_chi_rlc = eval_mle(&chi_rlc, &prs);
    assert_eq!(e_eq * (beta[0] * xor(e_chi_00, e_rc) + e_chi_rlc), pe);

    println!("");

    for step in 0..num_vars {
        let mut p = [Fr::zero(); 4];
        for i in 0..iota.len() {
            for k in 0..(1 << (num_vars - step - 1)) {
                let mut under_sum = to_poly(k)[0..(num_vars - step - 1)].to_vec();
                let mut eval = vec![Fr::zero(); step + 1];
                for k in 0..step {
                    eval[k] = prs[k];
                }
                eval[step] = Fr::zero();
                eval.extend_from_slice(&under_sum);
                assert_eq!(eval.len(), num_vars);
                // println!("eval st {step} i {i} @ 0: {eval:?}");

                let val = if i == 0 {
                    xor(eval_mle(&chi[i], &eval), eval_mle(&rc, &eval))
                } else {
                    eval_mle(&chi[i], &eval)
                };
                p[0] += beta[i] * eval_mle(&eq, &eval) * val;

                eval[step] = -Fr::one();
                let val = if i == 0 {
                    xor(eval_mle(&chi[i], &eval), eval_mle(&rc, &eval))
                } else {
                    eval_mle(&chi[i], &eval)
                };
                p[1] += beta[i] * eval_mle(&eq, &eval) * val;
            }
        }
        println!("step {step} v(0) = {}", p[0]);
        println!("step {step} v(-1) = {}", p[1]);
    }
}

#[test]
fn chi_no_recursion() {
    let input = [
        42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input.clone();
    let output = keccak_round(&mut buf, ROUND_CONSTANTS[0]);
    // output:
    // [0] - iota
    // [1] - chi
    // [2] - pi

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let pi = output[2].iter().map(|x| to_poly(*x)).collect::<Vec<_>>();
    let chi = output[1].iter().map(|x| to_poly(*x)).collect::<Vec<_>>();

    let real_chi_sum: Fr = chi
        .iter()
        .enumerate()
        .map(|(i, poly)| beta[i] * eval_mle(&poly, &alpha))
        .sum();

    let mut pi_sum = Fr::zero();
    for i in 0..25 {
        for k in 0..(1 << num_vars) {
            let e_chi = xor(
                pi[i][k],
                (Fr::one() - pi[add_col(i, 1)][k]) * pi[add_col(i, 2)][k],
            );
            assert_eq!(chi[i][k], e_chi);

            pi_sum += beta[i] * eq[k] * e_chi;
        }
    }
    assert_eq!(pi_sum, real_chi_sum);

    let (pe, prs) = {
        let mut eq = eq.clone();
        let mut pi = pi.clone();
        prove_sumcheck_chi(&mut prover, num_vars, &beta, &mut eq, &mut pi, &chi, real_chi_sum)
    };

    for step in 0..num_vars {
        let mut pm2 = Fr::zero();
        let mut pm1 = Fr::zero();
        let mut p0 = Fr::zero();
        let mut p1 = Fr::zero();
        let mut p2 = Fr::zero();

        for i in 0..chi.len() {
            for k in 0..(1 << (num_vars - step - 1)) {
                let mut under_sum = to_poly(k)[0..(num_vars - step - 1)].to_vec();
                let mut eval = vec![Fr::zero(); step + 1];
                for k in 0..step {
                    eval[k] = prs[k];
                }
                eval[step] = Fr::zero();
                eval.extend_from_slice(&under_sum);
                assert_eq!(eval.len(), num_vars);

                p0 += beta[i] * eval_mle(&eq, &eval) * xor(
                    eval_mle(&pi[i], &eval),
                    (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval)) * eval_mle(&pi[add_col(i, 2)], &eval),
                );

                eval[step] = -Fr::one();
                pm1 += beta[i] * eval_mle(&eq, &eval) * xor(
                    eval_mle(&pi[i], &eval),
                    (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval)) * eval_mle(&pi[add_col(i, 2)], &eval),
                );

                eval[step] = Fr::one() + Fr::one();
                p2 += beta[i] * eval_mle(&eq, &eval) * xor(
                    eval_mle(&pi[i], &eval),
                    (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval)) * eval_mle(&pi[add_col(i, 2)], &eval),
                );

                eval[step] = Fr::one();
                p1 += beta[i] * eval_mle(&eq, &eval) * xor(
                    eval_mle(&pi[i], &eval),
                    (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval)) * eval_mle(&pi[add_col(i, 2)], &eval),
                );

                eval[step] = - Fr::one() - Fr::one();
                pm2+= beta[i] * eval_mle(&eq, &eval) * xor(
                    eval_mle(&pi[i], &eval),
                    (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval)) * eval_mle(&pi[add_col(i, 2)], &eval),
                );

            }
        }

        println!("step {step} v(0) = {}", p0);
        println!("step {step} v(-1) = {}", pm1);
        println!("step {step} v(2) = {}", p2);
        println!("step {step} v(inf) = {}", (p2 + pm2 - Fr::from_str("4").unwrap() * (p1+pm1) + Fr::from_str("6").unwrap() * p0) / Fr::from_str("24").unwrap());

    }

    let mut checksum = Fr::zero();
    for i in 0..25 {
        checksum += beta[i] * xor(
            eval_mle(&pi[i], &prs),
            (Fr::one() - eval_mle(&pi[add_col(i, 1)], &prs)) * eval_mle(&pi[add_col(i, 2)], &prs),
        );
    }
    assert_eq!(
        eval_mle(&eq, &prs) * checksum,
        pe
    );
}

fn main() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input.clone();
    let output = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

    println!("inp {input:?}");
    println!("out {output:?}");

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    // run sumcheck on $\sum_k eq(\alpha, k) ⋅ [\beta_00 ⋅ (\chi00(k) xor RC(k)) + \sum_ij \beta_ij\chi_ij(k)]
    // we have 4 polynomials:
    // - eq(\alpha, k)
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    // - \chi_{00}(k)
    let chi_00 = to_poly(output[1][0]);
    // - RC(k)
    let rc = to_poly(ROUND_CONSTANTS[0]);
    // - \sum_{ij} \beta_{ij}\chi_{ij}(k) where (i, j) != (0, 0)
    let mut chi_rlc = vec![Fr::ZERO; 1 << num_vars];
    for el in 1..25 {
        // iterating from 1 to skip the first state element (i, j) = (0, 0)
        let poly = to_poly(output[1][el]);
        for x in 0..(1 << num_vars) {
            chi_rlc[x] += beta[el] * poly[x];
        }
    }

    let real_iota_sum: Fr = output[0]
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let poly = to_poly(*x);
            beta[i] * eval_mle(&poly, &alpha)
        })
        .sum();

    let sum = izip!(&eq, &chi_00, &rc, &chi_rlc)
        .map(|(&a, &b, &c, &d)| a * ((beta[0] * xor(b, c)) + d))
        .sum();

    assert_eq!(sum, real_iota_sum);

    // Prove
    prover.write(sum);
    let (pe, prs, (p_chi_00, p_chi_rlc)) = {
        let mut eq = eq.clone();
        let mut chi_00 = chi_00.clone();
        let mut rc = rc.clone();
        let mut chi_rlc = chi_rlc.clone();
        prove_sumcheck_iota(
            &mut prover,
            num_vars,
            beta[0],
            &mut eq,
            &mut chi_00,
            &mut rc,
            &mut chi_rlc,
            sum,
        )
    };

    // let proof = prover.finish();
    let e_eq = eval_mle(&eq, &prs); // TODO: can evaluate eq faster
    let e_chi_00 = eval_mle(&chi_00, &prs);
    let e_rc = eval_mle(&rc, &prs);
    let e_chi_rlc = eval_mle(&chi_rlc, &prs);
    assert_eq!(p_chi_00, e_chi_00);
    assert_eq!(p_chi_rlc, e_chi_rlc);
    assert_eq!(e_eq * (beta[0] * xor(e_chi_00, e_rc) + e_chi_rlc), pe);

    // chi
    let (pe_chi, prs_chi) = {
        let x = prover.read();
        let y = prover.read();
        println!("prover rlc {x} {y} {p_chi_00} {p_chi_rlc}");
        let mut beta = beta.clone();
        beta[0] *= x;
        beta.iter_mut().skip(1).for_each(|b| *b *= y);

        let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&prs);
        let eq_clone = eq.clone();
        let mut pi = output[2].iter().map(|u| to_poly(*u)).collect::<Vec<_>>();
        let pi_clone = pi.clone();
        let sum = beta[0] * p_chi_00 + y * p_chi_rlc;
        println!("expected sum prover {sum}");

        let real_chi_sum: Fr = output[1]
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let poly = to_poly(*x);
                beta[i] * eval_mle(&poly, &prs)
            })
            .sum();

        let chi = output[1].iter().map(|u| to_poly(*u)).collect::<Vec<_>>();

        let mut pi_sum = Fr::zero();
        for i in 0..(1 << num_vars) {
            for j in 0..pi.len() {
                pi_sum += beta[j]
                    * eq[i]
                    * xor(
                        pi[j][i],
                        (Fr::one() - pi[add_col(j, 1)][i]) * pi[add_col(j, 2)][i],
                    );
                assert_eq!(
                    chi[j][i],
                    xor(
                        pi[j][i],
                        (Fr::one() - pi[add_col(j, 1)][i]) * pi[add_col(j, 2)][i]
                    )
                );
            }
        }

        assert_eq!(sum, pi_sum);
        assert_eq!(sum, real_chi_sum);

        let (pe, prs) =
            prove_sumcheck_chi(&mut prover, num_vars, &beta, &mut eq, &mut pi, &chi, sum);

        let e_eq = eval_mle(&eq_clone, &prs); // TODO: can evaluate eq faster
        let pi = pi_clone
            .iter()
            .map(|p| eval_mle(&p, &prs))
            .collect::<Vec<_>>();
        println!("e_eq {e_eq}");
        println!("e_pi {pi:?}");

        let chi = chi.iter().map(|p| eval_mle(&p, &prs)).collect::<Vec<_>>();

        let mut checksum_pi = Fr::zero();
        let mut checksum_chi = Fr::zero();
        for i in 0..pi.len() {
            checksum_pi +=
                e_eq * beta[i] * xor(pi[i], (Fr::one() - pi[add_col(i, 1)]) * (pi[add_col(i, 2)]));
            checksum_chi += beta[i] * chi[i];
        }
        println!("checksum {checksum_pi} {checksum_chi} res {pe}");
        assert_eq!(checksum_pi, pe);

        (pe, prs)
    };

    let proof = prover.finish();

    // Verify
    let expected_sum = (0..25)
        .map(|i| beta[i] * eval_mle(&to_poly(output[0][i]), &alpha))
        .sum();

    let mut verifier = Verifier::new(&proof);

    // TODO: feed output to the prover/verifier before obtaining alpha
    let alpha = (0..num_vars)
        .map(|_| verifier.generate())
        .collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    let vs = verifier.read();
    assert_eq!(vs, expected_sum);
    let (ve, vrs) = verify_sumcheck::<3>(&mut verifier, num_vars, vs);
    assert_eq!(vrs, prs);
    assert_eq!(ve, pe);

    let chi_00 = verifier.read();
    let chi_rlc = verifier.read();
    assert_eq!(e_eq * (beta[0] * xor(chi_00, e_rc) + chi_rlc), pe);

    let x = verifier.generate();
    let y = verifier.generate();
    println!("verifier rlc {x} {y} {chi_00} {chi_rlc}");
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);

    // TODO: verifier needs to combine sublaims and continue recursively before we get to the last step
    let expected_sum = beta[0] * chi_00 + y * chi_rlc;
    println!("expected sum verifier {expected_sum}");

    let (ve, vrs) = verify_sumcheck::<4>(&mut verifier, num_vars, expected_sum);
    assert_eq!(vrs, prs_chi);
    assert_eq!(ve, pe_chi);

    // Verify last step
    //
    // NOTE: being lazy here, we've already tested prs and pe values after proving step.
    // Here just making sure they are the same. In practice, this should be a separate implementation.
}
