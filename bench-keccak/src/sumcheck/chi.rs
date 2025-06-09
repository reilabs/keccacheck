use ark_bn254::Fr;
use ark_ff::{One, Zero};
use std::str::FromStr;

use crate::sumcheck::util::{add_col, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly};
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
    pi: &[u64],
    sum: Fr,
) -> ChiProof {
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(r);
    let mut pi = pi.iter().map(|u| to_poly(*u)).collect::<Vec<_>>();

    let (pe, prs, pi) =
        prove_sumcheck_chi(transcript, num_vars, &beta, &mut eq, &mut pi, sum);

    ChiProof {
        sum: pe,
        r: prs,
        pi,
    }
}

/// Sumcheck for $\sum_x e(x) ⋅ (\sum_ij \beta_ij ⋅ xor(\pi_{ij}, not(\pi_{i+1,j}) ⋅ \pi_{i+2, j}))$.
pub fn prove_sumcheck_chi(
    transcript: &mut Prover,
    size: usize,
    beta: &[Fr],
    mut e: &mut [Fr],
    mut pis: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> (Fr, Vec<Fr>, Vec<Fr>) {
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
    (sum, rs, subclaims)
}
