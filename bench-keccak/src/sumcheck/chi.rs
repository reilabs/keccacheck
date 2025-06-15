use ark_bn254::Fr;
use ark_ff::{One, Zero};
use std::str::FromStr;

use crate::reference::{apply_pi, apply_pi_t, keccak_round, ROUND_CONSTANTS, STATE};
use crate::sumcheck::util::{add_col, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly, to_poly_multi};
use crate::{
    sumcheck::util::{HALF, update, xor},
    transcript::Prover,
};

pub struct ChiProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub pi: Vec<Fr>,
}

pub fn prove_chi(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta: &[Fr],
    rho: &[u64],
    sum: Fr,
) -> ChiProof {
    let instances = 1 << (num_vars - 6);

    let mut pi = rho.to_vec();
    apply_pi_t(rho, &mut pi);

    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(r);
    let mut pis = pi.chunks_exact(instances).map(|x| to_poly_multi(x)).collect::<Vec<_>>();

    let proof = prove_sumcheck_chi(transcript, num_vars, beta, &mut eq, &mut pis, sum);

    #[cfg(debug_assertions)]
    {
        // sumcheck consumed all polynomials. create again
        let eq = calculate_evaluations_over_boolean_hypercube_for_eq(r);
        let e_eq = eval_mle(&eq, &proof.r); // TODO: can evaluate eq faster

        let pi = pi
            .iter()
            .map(|u| {
                let poly = to_poly(*u);
                eval_mle(&poly, &proof.r)
            })
            .collect::<Vec<_>>();
        let mut checksum_pi = Fr::zero();

        for i in 0..pi.len() {
            checksum_pi +=
                e_eq * beta[i] * xor(pi[i], (Fr::one() - pi[add_col(i, 1)]) * (pi[add_col(i, 2)]));
        }
        assert_eq!(checksum_pi, proof.sum);
    }

    proof
}

/// Sumcheck for $\sum_x e(x) ⋅ (\sum_ij \beta_ij ⋅ xor(\pi_{ij}, not(\pi_{i+1,j}) ⋅ \pi_{i+2, j}))$.
pub fn prove_sumcheck_chi(
    transcript: &mut Prover,
    size: usize,
    beta: &[Fr],
    mut e: &mut [Fr],
    pis: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> ChiProof {
    assert_eq!(e.len(), 1 << size);
    pis.iter().for_each(|pi| {
        assert_eq!(pi.len(), 1 << size);
    });

    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2 + p3 ⋅ x^3 + p4 ⋅ x^4
        let mut p0 = Fr::zero();
        let mut pem1 = Fr::zero();
        let mut pe2 = Fr::zero();
        let mut p4 = Fr::zero();
        let (e0, e1) = e.split_at(e.len() / 2);
        let pi = pis
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();

        for i in 0..e0.len() {
            for j in 0..pi.len() {
                // Evaluation at 0
                p0 += e0[i]
                    * beta[j]
                    * xor(
                        pi[j].0[i],
                        (Fr::one() - pi[add_col(j, 1)].0[i]) * pi[add_col(j, 2)].0[i],
                    );

                // Evaluation at -1
                let eem1 = e0[i] + e0[i] - e1[i];
                // TODO: these values can be calculated once
                let piem1 = pi[j].0[i] + pi[j].0[i] - pi[j].1[i];
                let piem1_5 =
                    pi[add_col(j, 1)].0[i] + pi[add_col(j, 1)].0[i] - pi[add_col(j, 1)].1[i];
                let piem1_10 =
                    pi[add_col(j, 2)].0[i] + pi[add_col(j, 2)].0[i] - pi[add_col(j, 2)].1[i];
                pem1 += eem1 * beta[j] * xor(piem1, (Fr::one() - piem1_5) * piem1_10);

                // Evaluation at ∞
                let beta_m2 = -beta[j] - beta[j];
                p4 += beta_m2
                    * (e1[i] - e0[i])
                    * (pi[j].1[i] - pi[j].0[i])
                    * (pi[add_col(j, 1)].0[i] - pi[add_col(j, 1)].1[i])
                    * (pi[add_col(j, 2)].1[i] - pi[add_col(j, 2)].0[i]);

                // Evaluation at 2
                let ee2 = e1[i] + e1[i] - e0[i];
                let pie2 = pi[j].1[i] + pi[j].1[i] - pi[j].0[i];
                let pie2_5 =
                    pi[add_col(j, 1)].1[i] + pi[add_col(j, 1)].1[i] - pi[add_col(j, 1)].0[i];
                let pie2_10 =
                    pi[add_col(j, 2)].1[i] + pi[add_col(j, 2)].1[i] - pi[add_col(j, 2)].0[i];
                pe2 += ee2 * beta[j] * xor(pie2, (Fr::one() - pie2_5) * pie2_10);
            }
        }

        // Compute p1, p2, p3 from
        //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3 + p4
        //  p(-1) = p0 - p1 + p2 - p3 + p4
        //  p(2) = p0 + 2 ⋅ p1 + 4 ⋅ p2 + 8 ⋅ p3 + 16 ⋅ p4

        // TODO: coefficient calculations need to be optimized
        let pe1 = sum - p0;

        let p2 = HALF * (pe1 + pem1 - p4 - p4 - p0 - p0);

        let alpha = pe1 - pem1;
        let beta = pe2 - Fr::from_str("16").unwrap() * p4 - Fr::from_str("4").unwrap() * p2 - p0;

        let p1 = (Fr::from_str("4").unwrap() * alpha - beta) / Fr::from_str("6").unwrap();
        let p3 = (beta - alpha) / Fr::from_str("6").unwrap();

        assert_eq!(sum, p0 + p0 + p1 + p2 + p3 + p4);
        assert_eq!(pem1, p0 - p1 + p2 - p3 + p4);
        let two = Fr::one() + Fr::one();
        assert_eq!(pe2, ((((p4 * two) + p3) * two + p2) * two + p1) * two + p0);

        transcript.write(p1);
        transcript.write(p2);
        transcript.write(p3);
        transcript.write(p4);

        let r = transcript.read();
        rs.push(r);
        // TODO: Fold update into evaluation loop.
        e = update(e, r);
        for j in 0..pis.len() {
            // TODO: unnecessary allocation
            pis[j] = update(&mut pis[j], r).to_vec()
        }
        sum = p0 + r * (p1 + r * (p2 + r * (p3 + r * p4)));
    }
    let mut subclaims = Vec::with_capacity(pis.len());
    for j in 0..pis.len() {
        transcript.write(pis[j][0]);
        subclaims.push(pis[j][0]);
    }

    let mut checksum = Fr::zero();
    for j in 0..pis.len() {
        checksum += e[0]
            * beta[j]
            * xor(
                pis[j][0],
                (Fr::one() - pis[add_col(j, 1)][0]) * pis[add_col(j, 2)][0],
            );
    }
    assert_eq!(sum, checksum);
    ChiProof {
        sum,
        r: rs,
        pi: subclaims,
    }
}

#[test]
fn pi_chi_no_recursion() {
    let num_vars = 7; // two instances
    let instances = 1usize << (num_vars - 6);

    let mut data = (0..(instances * STATE)).map(|i| i as u64).collect::<Vec<_>>();
    let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let mut pi = state.rho.to_vec();
    apply_pi_t(&state.rho, &mut pi);
    let pi = pi.chunks_exact(instances).map(|x| to_poly_multi(x)).collect::<Vec<_>>();
    let chi = state
        .pi_chi
        .chunks_exact(instances)
        .map(|x| to_poly_multi(x))
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

        // println!("step {step} v(0) = {}", p0);
        // println!("step {step} v(-1) = {}", pm1);
        // println!("step {step} v(2) = {}", p2);
        // println!(
        //     "step {step} v(inf) = {}",
        //     (p2 + pm2 - Fr::from_str("4").unwrap() * (p1 + pm1) + Fr::from_str("6").unwrap() * p0)
        //         / Fr::from_str("24").unwrap()
        // );
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
