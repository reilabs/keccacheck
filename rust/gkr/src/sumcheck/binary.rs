// Functionality for checking that a polynomial has boolean evaluations over the hypercube
// This confirms that B(x) = \sum_i eq(x,i)b(i)(1 - b(i)) = 0

use crate::sumcheck::util::{
    HALF, calculate_evaluations_over_boolean_hypercube_for_eq, eq, update, verify_sumcheck,
};
use crate::transcript::{Prover, Verifier};
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use rayon::prelude::*;
use tracing::instrument;

pub struct BinaryProof {
    pub r_x: Vec<Fr>,
    pub bits_rlc_eval: Vec<Fr>,
}

/// Proves that k bit polynomials have boolean evaluations over the hypercube.
///
/// Runs a degree-3 sumcheck proving:
/// $$\sum_{x \in \{0,1\}^n} \widetilde{eq}(\alpha, x) \cdot \sum_j \beta_j \cdot b_j(x) \cdot (1 - b_j(x)) = 0$$
///
/// After the sumcheck, reveals the individual evaluations $b_j(r_x)$ as subclaims.
#[instrument(skip_all)]
pub fn prove_binary(
    transcript: &mut Prover,
    num_vars: usize,
    alpha: &[Fr],
    bits: &mut [Vec<Fr>],
    beta: &[Fr],
) -> BinaryProof {
    let k = bits.len();
    assert_eq!(beta.len(), k);
    assert!(bits.iter().all(|b| b.len() == 1 << num_vars));

    let mut eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(alpha);

    #[cfg(debug_assertions)]
    {
        let mut c_sum = Fr::zero();
        for x in 0..(1 << num_vars) {
            for j in 0..k {
                c_sum += eq_alpha[x] * beta[j] * bits[j][x] * (Fr::one() - bits[j][x]);
            }
        }
        assert_eq!(c_sum, Fr::zero());
    }

    prove_sumcheck_binary(transcript, num_vars, &mut eq_alpha, bits, beta)
}

/// Sumcheck for $\sum_x e(x) \cdot \sum_j \beta_j \cdot b_j(x) \cdot (1 - b_j(x))$.
///
/// Degree-3 polynomial per round: eq (deg 1) × b (deg 1) × (1−b) (deg 1).
#[instrument(skip_all)]
fn prove_sumcheck_binary(
    transcript: &mut Prover,
    size: usize,
    mut e: &mut [Fr],
    bits: &mut [Vec<Fr>],
    beta: &[Fr],
) -> BinaryProof {
    let k = bits.len();
    assert_eq!(e.len(), 1 << size);

    let mut sum = Fr::zero();
    let mut rs = Vec::with_capacity(size);

    for _ in 0..size {
        // p(t) = p0 + p1 ⋅ t + p2 ⋅ t² + p3 ⋅ t³
        let (e0, e1) = e.split_at(e.len() / 2);
        let bi: Vec<(&[Fr], &[Fr])> = bits
            .iter()
            .map(|b| b.split_at(b.len() / 2))
            .collect();

        let (p0, pem1, p3) = bi
            .par_iter()
            .enumerate()
            .map(|(j, &(b0, b1))| {
                let mut p0 = Fr::zero();
                let mut pem1 = Fr::zero();
                let mut p3 = Fr::zero();

                for i in 0..e0.len() {
                    // Evaluation at 0: e0 * b0 * (1 - b0)
                    p0 += e0[i] * (b0[i] - b0[i] * b0[i]);

                    // Evaluation at -1
                    let eem1 = e0[i] + e0[i] - e1[i];
                    let bem1 = b0[i] + b0[i] - b1[i];
                    pem1 += eem1 * (bem1 - bem1 * bem1);

                    // Leading coefficient (t³): −(e1−e0)⋅(b1−b0)²
                    let de = e1[i] - e0[i];
                    let db = b1[i] - b0[i];
                    p3 -= de * db * db;
                }

                (beta[j] * p0, beta[j] * pem1, beta[j] * p3)
            })
            .reduce_with(|a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2))
            .unwrap();

        // Derive p1, p2 from:
        //   p(0) + p(1) = 2⋅p0 + p1 + p2 + p3 = sum
        //   p(−1) = p0 − p1 + p2 − p3 = pem1
        let p2 = HALF * (sum + pem1 - p0) - p0;
        let p1 = sum - p0 - p0 - p3 - p2;
        assert_eq!(p0 + p0 + p1 + p2 + p3, sum);

        transcript.write(p1);
        transcript.write(p2);
        transcript.write(p3);

        let r = transcript.read();
        rs.push(r);

        (e, _) = rayon::join(
            || update(e, r),
            || {
                bits.par_iter_mut().for_each(|b| {
                    *b = update(b, r).to_vec();
                });
            },
        );

        // Update sum = p(r)
        sum = p0 + r * (p1 + r * (p2 + r * p3));
    }

    // Write individual evaluations as subclaims
    let mut evals = Vec::with_capacity(k);
    for b in bits.iter() {
        transcript.write(b[0]);
        evals.push(b[0]);
    }

    #[cfg(debug_assertions)]
    {
        let mut checksum = Fr::zero();
        for j in 0..k {
            checksum += e[0] * beta[j] * bits[j][0] * (Fr::one() - bits[j][0]);
        }
        assert_eq!(sum, checksum);
    }

    BinaryProof {
        r_x: rs,
        bits_rlc_eval: evals,
    }
}

pub fn verify_binary(
    transcript: &mut Verifier,
    num_vars: usize,
    alpha: &[Fr],
    beta: &[Fr],
    num_polys: usize,
) -> BinaryProof {
    let (final_val, r_x) = verify_sumcheck::<3>(transcript, num_vars, Fr::zero());

    let evals: Vec<Fr> = (0..num_polys).map(|_| transcript.read()).collect();

    let eq_val = eq(alpha, &r_x);
    let mut checksum = Fr::zero();
    for j in 0..num_polys {
        checksum += beta[j] * evals[j] * (Fr::one() - evals[j]);
    }
    assert_eq!(final_val, eq_val * checksum);

    BinaryProof {
        r_x,
        bits_rlc_eval: evals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sumcheck::util::eval_mle;
    use crate::transcript::Prover;

    #[test]
    fn binary_proof_roundtrip() {
        let num_vars = 3;
        let k = 2;

        let bits0: Vec<Fr> = [0, 1, 1, 0, 1, 0, 0, 1]
            .iter()
            .map(|&x| Fr::from(x as u64))
            .collect();
        let bits1: Vec<Fr> = [1, 0, 1, 1, 0, 0, 1, 0]
            .iter()
            .map(|&x| Fr::from(x as u64))
            .collect();

        let mut prover = Prover::new();
        let alpha: Vec<Fr> = (0..num_vars).map(|_| prover.read()).collect();
        let beta: Vec<Fr> = (0..k).map(|_| prover.read()).collect();

        let bits0_orig = bits0.clone();
        let bits1_orig = bits1.clone();
        let mut bits = vec![bits0, bits1];
        let proof = prove_binary(&mut prover, num_vars, &alpha, &mut bits, &beta);

        // Verify
        let proof_data = prover.finish();
        let mut verifier = Verifier::new(&proof_data);
        let v_alpha: Vec<Fr> = (0..num_vars).map(|_| verifier.generate()).collect();
        let v_beta: Vec<Fr> = (0..k).map(|_| verifier.generate()).collect();

        assert_eq!(alpha, v_alpha);
        assert_eq!(beta, v_beta);

        let v_proof = verify_binary(&mut verifier, num_vars, &v_alpha, &v_beta, k);

        assert_eq!(proof.r_x, v_proof.r_x);
        assert_eq!(proof.bits_rlc_eval, v_proof.bits_rlc_eval);

        // Check evaluations match original polynomials
        assert_eq!(proof.bits_rlc_eval[0], eval_mle(&bits0_orig, &proof.r_x));
        assert_eq!(proof.bits_rlc_eval[1], eval_mle(&bits1_orig, &proof.r_x));
    }

    #[test]
    fn binary_proof_single_poly() {
        let num_vars = 4;

        let bits0: Vec<Fr> = (0..16).map(|x| Fr::from((x % 2) as u64)).collect();

        let mut prover = Prover::new();
        let alpha: Vec<Fr> = (0..num_vars).map(|_| prover.read()).collect();
        let beta: Vec<Fr> = (0..1).map(|_| prover.read()).collect();

        let bits0_orig = bits0.clone();
        let mut bits = vec![bits0];
        let proof = prove_binary(&mut prover, num_vars, &alpha, &mut bits, &beta);

        let proof_data = prover.finish();
        let mut verifier = Verifier::new(&proof_data);
        let v_alpha: Vec<Fr> = (0..num_vars).map(|_| verifier.generate()).collect();
        let v_beta: Vec<Fr> = (0..1).map(|_| verifier.generate()).collect();

        let v_proof = verify_binary(&mut verifier, num_vars, &v_alpha, &v_beta, 1);

        assert_eq!(proof.r_x, v_proof.r_x);
        assert_eq!(proof.bits_rlc_eval[0], eval_mle(&bits0_orig, &proof.r_x));
    }
}
