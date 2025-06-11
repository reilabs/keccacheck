use crate::sumcheck::theta::{prove_sumcheck_theta, prove_theta};
use crate::reference::{ROUND_CONSTANTS, apply_pi, keccak_round};
use crate::sumcheck::chi::prove_sumcheck_chi;
use crate::sumcheck::iota::prove_sumcheck_iota;
use crate::sumcheck::rho::{calculate_evaluations_over_boolean_hypercube_for_rot, prove_rho};
use crate::sumcheck::util::{add_col, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly, to_poly_xor_base, xor};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use std::str::FromStr;

#[test]
fn iota_no_recursion() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input;
    let output = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let chi_00 = to_poly(output.pi_chi[0]);
    let rc = to_poly(ROUND_CONSTANTS[0]);
    let mut chi_rlc = vec![Fr::zero(); 1 << num_vars];
    for el in 1..25 {
        // iterating from 1 to skip the first state element (i, j) = (0, 0)
        let poly = to_poly(output.pi_chi[el]);
        for x in 0..(1 << num_vars) {
            chi_rlc[x] += beta[el] * poly[x];
        }
    }
    let chi = output
        .pi_chi
        .iter()
        .map(|x| to_poly(*x))
        .collect::<Vec<_>>();
    let iota = output.iota.iter().map(|x| to_poly(*x)).collect::<Vec<_>>();

    let real_iota_sum: Fr = iota
        .iter()
        .enumerate()
        .map(|(i, poly)| beta[i] * eval_mle(poly, &alpha))
        .sum();

    let (pe, prs) = {
        let mut eq = eq.clone();
        let mut chi_00 = chi_00.clone();
        let mut rc = rc.clone();
        let mut chi_rlc = chi_rlc.clone();
        let proof = prove_sumcheck_iota(
            &mut prover,
            num_vars,
            beta[0],
            &mut eq,
            &mut chi_00,
            &mut rc,
            &mut chi_rlc,
            real_iota_sum,
        );
        (proof.sum, proof.r)
    };
    let e_eq = eval_mle(&eq, &prs); // TODO: can evaluate eq faster
    let e_chi_00 = eval_mle(&chi_00, &prs);
    let e_rc = eval_mle(&rc, &prs);
    let e_chi_rlc = eval_mle(&chi_rlc, &prs);
    assert_eq!(e_eq * (beta[0] * xor(e_chi_00, e_rc) + e_chi_rlc), pe);

    println!();

    for step in 0..num_vars {
        let mut p = [Fr::zero(); 4];
        for i in 0..iota.len() {
            for k in 0..(1 << (num_vars - step - 1)) {
                let under_sum = to_poly(k)[0..(num_vars - step - 1)].to_vec();
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
fn pi_chi_no_recursion() {
    let input = [
        42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input;
    let output = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let mut pi = output.rho.to_vec();
    apply_pi(&output.rho, &mut pi);
    let pi = pi.iter().map(|x| to_poly(*x)).collect::<Vec<_>>();
    let chi = output
        .pi_chi
        .iter()
        .map(|x| to_poly(*x))
        .collect::<Vec<_>>();

    let real_chi_sum: Fr = chi
        .iter()
        .enumerate()
        .map(|(i, poly)| beta[i] * eval_mle(poly, &alpha))
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

    let proof = {
        let mut eq = eq.clone();
        let mut pi = pi.clone();
        prove_sumcheck_chi(&mut prover, num_vars, &beta, &mut eq, &mut pi, real_chi_sum)
    };

    for step in 0..num_vars {
        let mut pm2 = Fr::zero();
        let mut pm1 = Fr::zero();
        let mut p0 = Fr::zero();
        let mut p1 = Fr::zero();
        let mut p2 = Fr::zero();

        for i in 0..chi.len() {
            for k in 0..(1 << (num_vars - step - 1)) {
                let under_sum = to_poly(k)[0..(num_vars - step - 1)].to_vec();
                let mut eval = vec![Fr::zero(); step + 1];
                for k in 0..step {
                    eval[k] = proof.r[k];
                }
                eval[step] = Fr::zero();
                eval.extend_from_slice(&under_sum);
                assert_eq!(eval.len(), num_vars);

                p0 += beta[i]
                    * eval_mle(&eq, &eval)
                    * xor(
                        eval_mle(&pi[i], &eval),
                        (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval))
                            * eval_mle(&pi[add_col(i, 2)], &eval),
                    );

                eval[step] = -Fr::one();
                pm1 += beta[i]
                    * eval_mle(&eq, &eval)
                    * xor(
                        eval_mle(&pi[i], &eval),
                        (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval))
                            * eval_mle(&pi[add_col(i, 2)], &eval),
                    );

                eval[step] = Fr::one() + Fr::one();
                p2 += beta[i]
                    * eval_mle(&eq, &eval)
                    * xor(
                        eval_mle(&pi[i], &eval),
                        (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval))
                            * eval_mle(&pi[add_col(i, 2)], &eval),
                    );

                eval[step] = Fr::one();
                p1 += beta[i]
                    * eval_mle(&eq, &eval)
                    * xor(
                        eval_mle(&pi[i], &eval),
                        (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval))
                            * eval_mle(&pi[add_col(i, 2)], &eval),
                    );

                eval[step] = -Fr::one() - Fr::one();
                pm2 += beta[i]
                    * eval_mle(&eq, &eval)
                    * xor(
                        eval_mle(&pi[i], &eval),
                        (Fr::one() - eval_mle(&pi[add_col(i, 1)], &eval))
                            * eval_mle(&pi[add_col(i, 2)], &eval),
                    );
            }
        }

        println!("step {step} v(0) = {}", p0);
        println!("step {step} v(-1) = {}", pm1);
        println!("step {step} v(2) = {}", p2);
        println!(
            "step {step} v(inf) = {}",
            (p2 + pm2 - Fr::from_str("4").unwrap() * (p1 + pm1) + Fr::from_str("6").unwrap() * p0)
                / Fr::from_str("24").unwrap()
        );
    }

    let mut checksum = Fr::zero();
    for i in 0..25 {
        checksum += beta[i]
            * xor(
                eval_mle(&pi[i], &proof.r),
                (Fr::one() - eval_mle(&pi[add_col(i, 1)], &proof.r))
                    * eval_mle(&pi[add_col(i, 2)], &proof.r),
            );
    }
    assert_eq!(eval_mle(&eq, &proof.r) * checksum, proof.sum);
}

#[test]
fn rho_no_recursion() {
    let input = [
        42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input;
    let output = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let rho = output.rho.iter().map(|x| to_poly(*x)).collect::<Vec<_>>();

    let real_rho_sum: Fr = rho
        .iter()
        .enumerate()
        .map(|(i, poly)| beta[i] * eval_mle(poly, &alpha))
        .sum();

    let proof = prove_rho(
        &mut prover,
        num_vars,
        &alpha,
        &beta,
        &output.theta,
        real_rho_sum,
    );

    let rot = (0..25)
        .map(|i| calculate_evaluations_over_boolean_hypercube_for_rot(&alpha, i))
        .collect::<Vec<_>>();
    let theta = output.theta.iter().map(|x| to_poly(*x)).collect::<Vec<_>>();
    //
    // let mut theta_sum = Fr::zero();
    // for i in 0..25 {
    //     for k in 0..(1 << num_vars) {
    //         theta_sum += beta[i] * rot[i][k] * theta[i][k];
    //     }
    // }
    // assert_eq!(theta_sum, real_rho_sum);
    //
    // let proof = {
    //     let mut rots = rot.clone();
    //     let mut thetas = theta.clone();
    //     prove_sumcheck_rho(&mut prover, num_vars, &beta, &mut rots, &mut thetas, real_rho_sum)
    // };
    //
    let mut checksum = Fr::zero();
    for i in 0..25 {
        checksum += beta[i] * eval_mle(&rot[i], &proof.r) * eval_mle(&theta[i], &proof.r);
    }
    assert_eq!(checksum, proof.sum);
}

#[test]
fn theta_no_recursion() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input;
    let state = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let theta = state.theta.iter().map(|x| to_poly_xor_base(*x)).collect::<Vec<_>>();
    let real_theta_sum: Fr = theta
        .iter()
        .enumerate()
        .map(|(i, poly)| beta[i] * eval_mle(poly, &alpha))
        .sum();

    prove_theta(
        &mut prover,
        num_vars,
        &alpha,
        &beta,
        &state.d,
        &state.a,
        real_theta_sum,
    );
}