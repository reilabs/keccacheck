use crate::sumcheck::util::{
    calculate_evaluations_over_boolean_hypercube_for_eq, to_poly_xor_base,
};
use crate::{sumcheck::util::update, transcript::Prover};
use ark_bn254::Fr;
use ark_ff::Zero;
use rayon::prelude::*;
use tracing::instrument;

pub struct ThetaAProof {
    pub _sum: Fr,
    pub r: Vec<Fr>,
    pub iota: Vec<Fr>,
}

#[instrument(skip_all)]
pub fn prove_theta_a(
    transcript: &mut Prover,
    num_vars: usize,
    r1: &[Fr],
    r2: &[Fr],
    beta1: &[Fr],
    beta2: &[Fr],
    a: &[u64],
    sum: Fr,
) -> ThetaAProof {
    let instances = 1 << (num_vars - 6);

    let ((mut eq1, mut eq2), mut a) = rayon::join(
        || {
            rayon::join(
                || calculate_evaluations_over_boolean_hypercube_for_eq(r1),
                || calculate_evaluations_over_boolean_hypercube_for_eq(r2),
            )
        },
        || {
            a.par_chunks_exact(instances)
                .map(to_poly_xor_base)
                .collect::<Vec<_>>()
        },
    );

    #[cfg(debug_assertions)]
    {
        let mut checksum = Fr::zero();
        for i in 0..a.len() {
            for x in 0..(1 << num_vars) {
                checksum += beta1[i] * eq1[x] * a[i][x] + beta2[i] * eq2[x] * a[i][x];
            }
        }
        assert_eq!(checksum, sum);
    }

    prove_sumcheck_theta_a(
        transcript, num_vars, beta1, beta2, &mut eq1, &mut eq2, &mut a, sum,
    )
}

pub fn prove_sumcheck_theta_a(
    transcript: &mut Prover,
    size: usize,
    beta_a: &[Fr],
    beta_b: &[Fr],
    mut eq_a: &mut [Fr],
    mut eq_b: &mut [Fr],
    aij: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> ThetaAProof {
    #[cfg(debug_assertions)]
    {
        assert_eq!(beta_a.len(), beta_b.len());
        assert_eq!(beta_a.len(), aij.len());
        assert_eq!(eq_a.len(), 1 << size);
        assert_eq!(eq_b.len(), 1 << size);
        aij.iter().for_each(|a| {
            assert_eq!(a.len(), 1 << size);
        });
    }

    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2
        let mut p0 = Fr::zero();
        let mut p2 = Fr::zero();

        let (ea0, ea1) = eq_a.split_at(eq_a.len() / 2);
        let (eb0, eb1) = eq_b.split_at(eq_b.len() / 2);
        let a = aij
            .iter()
            .map(|x| {
                let (a, _) = x.split_at(eq_a.len());
                a.split_at(ea0.len())
            })
            .collect::<Vec<_>>();

        let (p0t, p2t) = a
            .into_par_iter()
            .enumerate()
            .map(|(j, a)| {
                let ba = beta_a[j];
                let bb = beta_b[j];
                let a = a.0.iter().zip(a.1);

                let mut p0_a = Fr::zero();
                let mut p0_b = Fr::zero();
                let mut p2_a = Fr::zero();
                let mut p2_b = Fr::zero();

                for (i, (a0, a1)) in a.enumerate() {
                    // Evaluation at 0
                    p0_a += ea0[i] * a0;
                    p0_b += eb0[i] * a0;

                    // Evaluation at ∞
                    let v = a1 - a0;
                    p2_a += (ea1[i] - ea0[i]) * v;
                    p2_b += (eb1[i] - eb0[i]) * v;
                }

                (ba * p0_a + bb * p0_b, ba * p2_a + bb * p2_b)
            })
            .reduce_with(|a, b| (a.0 + b.0, a.1 + b.1))
            .unwrap();

        p0 += p0t;
        p2 += p2t;

        // Compute p1 from
        //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3 + p4
        let p1 = sum - p0 - p0 - p2;
        assert_eq!(sum, p0 + p0 + p1 + p2);

        transcript.write(p1);
        transcript.write(p2);

        let r = transcript.read();
        rs.push(r);

        // TODO: Fold update into evaluation loop.
        let len = eq_a.len();
        ((eq_a, eq_b), _) = rayon::join(
            || rayon::join(|| update(eq_a, r), || update(eq_b, r)),
            || {
                aij.par_iter_mut().for_each(|a| {
                    update(&mut a[0..len], r);
                });
            },
        );

        // for j in 0..aij.len() {
        //     update(&mut aij[j][0..len], r);
        // }
        sum = p0 + r * (p1 + r * p2);
    }

    let mut subclaims = Vec::with_capacity(aij.len());
    for j in 0..aij.len() {
        transcript.write(aij[j][0]);
        subclaims.push(aij[j][0]);
    }

    // check result
    #[cfg(debug_assertions)]
    {
        let mut checksum = Fr::zero();
        for j in 0..aij.len() {
            checksum += beta_a[j] * eq_a[0] * aij[j][0] + beta_b[j] * eq_b[0] * aij[j][0];
        }
        assert_eq!(sum, checksum);
    }

    ThetaAProof {
        _sum: sum,
        r: rs,
        iota: subclaims,
    }
}

#[cfg(test)]
mod test {
    use crate::reference::{ROUND_CONSTANTS, STATE, keccak_round};
    use crate::sumcheck::theta_a::prove_theta_a;
    use crate::sumcheck::util::{eval_mle, to_poly_xor_base};
    use crate::transcript::Prover;
    use ark_bn254::Fr;

    #[test]
    fn theta_a_no_recursion() {
        let num_vars = 7; // two instances
        let instances = 1usize << (num_vars - 6);

        let mut data = (0..(instances * STATE))
            .map(|i| i as u64)
            .collect::<Vec<_>>();
        let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

        let mut prover = Prover::new();
        let alpha_a = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
        let alpha_b = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();

        let beta_a = (0..STATE).map(|_| prover.read()).collect::<Vec<_>>();
        let beta_b = (0..STATE).map(|_| prover.read()).collect::<Vec<_>>();

        let result = state
            .a
            .chunks_exact(instances)
            .map(to_poly_xor_base)
            .collect::<Vec<_>>();
        let real_sum: Fr = result
            .iter()
            .enumerate()
            .map(|(i, poly)| {
                beta_a[i] * eval_mle(poly, &alpha_a) + beta_b[i] * eval_mle(poly, &alpha_b)
            })
            .sum();

        prove_theta_a(
            &mut prover,
            num_vars,
            &alpha_a,
            &alpha_b,
            &beta_a,
            &beta_b,
            &state.a,
            real_sum,
        );
    }
}
