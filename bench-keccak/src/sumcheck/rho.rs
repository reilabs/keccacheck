use ark_bn254::Fr;
use ark_ff::{One, Zero};
use std::str::FromStr;

use crate::sumcheck::util::{
    eval_mle, to_poly,
};
use crate::{
    sumcheck::util::{HALF, update, xor},
    transcript::Prover,
};

/// List of evaluations for rot_i(r, x) over the boolean hypercube
pub fn calculate_evaluations_over_boolean_hypercube_for_rot(r: &[Fr], i: usize) -> Vec<Fr> {
    todo!()
}

pub struct RhoProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub theta: Vec<Fr>,
}

pub fn prove_rho(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta: &[Fr],
    theta: &[u64],
    sum: Fr,
) -> RhoProof {
    let mut rots = (0..25).map(|i| {
        calculate_evaluations_over_boolean_hypercube_for_rot(&r, i)
    }).collect::<Vec<_>>();
    let mut thetas = theta.iter().map(|u| to_poly(*u)).collect::<Vec<_>>();

    let proof = prove_sumcheck_rho(transcript, num_vars, beta, &mut rots, &mut thetas, sum);

    #[cfg(debug_assertions)]
    {
        let checksum: Fr = theta
            .iter()
            .enumerate()
            .map(|(i, theta)| {
                let theta = to_poly(*theta);
                let rot = calculate_evaluations_over_boolean_hypercube_for_rot(&r, i);
                beta[i] * eval_mle(&theta, &proof.r) * eval_mle(&rot, &proof.r)
            })
            .sum();
        assert_eq!(checksum, proof.sum);
    }

    proof
}

/// Sumcheck for $\sum_x e(x) ⋅ (\sum_ij \beta_ij ⋅ xor(\pi_{ij}, not(\pi_{i+1,j}) ⋅ \pi_{i+2, j}))$.
pub fn prove_sumcheck_rho(
    transcript: &mut Prover,
    size: usize,
    beta: &[Fr],
    rots: &mut Vec<Vec<Fr>>,
    thetas: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> RhoProof {
    #[cfg(debug_assertions)]
    {
        rots.iter().for_each(|rot| {
            assert_eq!(rot.len(), 1 << size);
        });
        thetas.iter().for_each(|theta| {
            assert_eq!(theta.len(), 1 << size);
        });
    }

    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2
        let mut p0 = Fr::zero();
        let mut p2 = Fr::zero();
        let rot = rots
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();
        let theta = thetas
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();

        for i in 0..rot[0].0.len() {
            for j in 0..theta.len() {
                // Evaluation at 0
                p0 += beta[j]
                    * rot[j].0[i]
                    * theta[j].0[i];

                // Evaluation at ∞
                p2 += beta[j]
                    * (rot[j].1[i] - rot[j].0[i])
                    * (theta[j].1[i] - theta[j].0[i]);
            }
        }

        // Compute p1 from
        //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3 + p4
        let p1 = sum - p0 - p0 - p2;
        assert_eq!(sum, p0 + p0 + p1 + p2);

        transcript.write(p1);
        transcript.write(p2);

        let r = transcript.read();
        rs.push(r);
        // TODO: Fold update into evaluation loop.
        for j in 0..rots.len() {
            // TODO: unnecessary allocation
            rots[j] = update(&mut rots[j], r).to_vec();
            thetas[j] = update(&mut thetas[j], r).to_vec();
        }
        sum = p0 + r * (p1 + r * p2);
    }
    let mut subclaims = Vec::with_capacity(thetas.len());
    for j in 0..thetas.len() {
        transcript.write(thetas[j][0]);
        subclaims.push(thetas[j][0]);
    }

    let mut checksum = Fr::zero();
    for j in 0..thetas.len() {
        checksum += beta[j]
            * rots[j][0]
            * thetas[j][0];
    }
    assert_eq!(sum, checksum);
    RhoProof {
        sum,
        r: rs,
        theta: subclaims,
    }
}
