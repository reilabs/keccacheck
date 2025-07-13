use crate::sumcheck::util::{
    HALF, calculate_evaluations_over_boolean_hypercube_for_eq, to_poly_xor_base,
    to_poly_xor_base_coeff, update,
};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::Zero;
use rayon::prelude::*;
use tracing::instrument;

pub struct ThetaProof {
    pub _sum: Fr,
    pub r: Vec<Fr>,
    pub d: Vec<Fr>,
    pub ai: Vec<Fr>,
}

#[instrument(skip_all)]
pub fn prove_theta(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta: &[Fr],
    d: &[u64],
    a: &[u64],
    sum: Fr,
) -> ThetaProof {
    let instances = 1 << (num_vars - 6);

    let ((mut eq, mut d), mut ai) = rayon::join(
        || {
            rayon::join(
                || calculate_evaluations_over_boolean_hypercube_for_eq(r),
                || {
                    d.par_chunks_exact(instances)
                        .map(to_poly_xor_base)
                        .collect::<Vec<_>>()
                },
            )
        },
        || {
            (0..5)
                .into_par_iter()
                .map(|i| {
                    let mut rlc = vec![Fr::zero(); 1 << num_vars];
                    for j in 0..5 {
                        let id = j * 5 + i;
                        let idx = id * instances;
                        let poly = to_poly_xor_base_coeff(&a[idx..(idx + instances)], beta[id]);
                        for x in 0..(1 << num_vars) {
                            rlc[x] += poly[x];
                        }
                    }
                    rlc
                })
                .collect::<Vec<_>>()
        },
    );

    #[cfg(debug_assertions)]
    {
        let mut ai_d_sum = Fr::zero();
        for j in 0..d.len() {
            for (x, eq_el) in eq.iter().enumerate() {
                ai_d_sum += *eq_el * d[j][x] * ai[j][x];
            }
        }
        assert_eq!(ai_d_sum, sum);
    }

    prove_sumcheck_theta(transcript, num_vars, &mut eq, &mut d, &mut ai, sum)
}

#[instrument(skip_all)]
pub fn prove_sumcheck_theta(
    transcript: &mut Prover,
    size: usize,
    mut eq: &mut [Fr],
    ds: &mut Vec<Vec<Fr>>,
    ai_rlc: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> ThetaProof {
    #[cfg(debug_assertions)]
    {
        assert_eq!(eq.len(), 1 << size);
        assert_eq!(ds.len(), ai_rlc.len());
        ds.iter().for_each(|d| {
            assert_eq!(d.len(), 1 << size);
        });
        ai_rlc.iter().for_each(|ai| {
            assert_eq!(ai.len(), 1 << size);
        });
    }

    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2 + p3 ⋅ x^3
        let mut p0 = Fr::zero();
        let mut pem1 = Fr::zero();
        let mut p3 = Fr::zero();

        let (e0, e1) = eq.split_at(eq.len() / 2);
        let d = ds
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();
        let ai = ai_rlc
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();

        let (a, b, c) = (0..d.len())
            .into_par_iter()
            .map(|j| {
                let mut p0 = Fr::zero();
                let mut pem1 = Fr::zero();
                let mut p3 = Fr::zero();

                for i in 0..d[0].0.len() {
                    // Evaluation at 0
                    p0 += e0[i] * d[j].0[i] * ai[j].0[i];

                    // Evaluation at -1
                    pem1 += (e0[i] + e0[i] - e1[i])
                        * (d[j].0[i] + d[j].0[i] - d[j].1[i])
                        * (ai[j].0[i] + ai[j].0[i] - ai[j].1[i]);

                    // Evaluation at ∞
                    p3 += (e1[i] - e0[i]) * (d[j].1[i] - d[j].0[i]) * (ai[j].1[i] - ai[j].0[i]);
                }

                (p0, pem1, p3)
            })
            .reduce_with(|a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2))
            .unwrap();

        p0 += a;
        pem1 += b;
        p3 += c;

        // Compute p1 and p2 from
        //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3
        //  p(-1) = p0 - p1 + p2 - p3
        let p2 = HALF * (sum + pem1 - p0) - p0;
        let p1 = sum - p0 - p0 - p3 - p2;
        assert_eq!(sum, p0 + p0 + p1 + p2 + p3);
        assert_eq!(pem1, p0 - p1 + p2 - p3);

        transcript.write(p1);
        transcript.write(p2);
        transcript.write(p3);

        let r = transcript.read();
        rs.push(r);
        // TODO: Fold update into evaluation loop.
        (eq, _) = rayon::join(
            || update(eq, r),
            || {
                rayon::join(
                    || {
                        ds.par_iter_mut().for_each(|x| {
                            *x = update(x, r).to_vec();
                        });
                    },
                    || {
                        ai_rlc.par_iter_mut().for_each(|x| {
                            *x = update(x, r).to_vec();
                        });
                    },
                );
            },
        );

        // sum = p(r)
        sum = p0 + r * (p1 + r * (p2 + r * p3));
    }

    let mut ai_subclaims = Vec::with_capacity(ai_rlc.len());
    for ai_rlc_elem in ai_rlc.iter() {
        transcript.write(ai_rlc_elem[0]);
        ai_subclaims.push(ai_rlc_elem[0]);
    }

    let mut d_subclaims = Vec::with_capacity(ds.len());
    for ds_elem in ds.iter() {
        transcript.write(ds_elem[0]);
        d_subclaims.push(ds_elem[0]);
    }

    // check result
    #[cfg(debug_assertions)]
    {
        let mut checksum = Fr::zero();
        for j in 0..ds.len() {
            checksum += eq[0] * ds[j][0] * ai_rlc[j][0];
        }
        assert_eq!(sum, checksum);
    }

    ThetaProof {
        _sum: sum,
        r: rs,
        d: d_subclaims,
        ai: ai_subclaims,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{STATE, keccak_round};
    use crate::sumcheck::util::{eval_mle, to_poly};
    use ark_ff::One;
    #[test]
    fn theta_no_recursion() {
        let num_vars = 7; // two instances
        let instances = 1usize << (num_vars - 6);

        let data = (0..(instances * STATE))
            .map(|i| i as u64)
            .collect::<Vec<_>>();
        let state = keccak_round(&data, 0);

        let mut prover = Prover::new();
        let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
        let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

        let real_theta_sum: Fr = state
            .theta
            .chunks_exact(instances)
            .map(to_poly)
            .map(|poly| eval_mle(&poly, &alpha))
            .map(|x| Fr::one() - x - x)
            .enumerate()
            .map(|(i, x)| beta[i] * x)
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
}
