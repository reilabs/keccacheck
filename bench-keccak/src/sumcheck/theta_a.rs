use crate::sumcheck::util::{calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, partial_eval_mle, to_poly, to_poly_xor_base, to_poly_xor_base_multi};
use crate::{sumcheck::util::update, transcript::Prover};
use ark_bn254::Fr;
use ark_ff::{One, Zero};

pub struct ThetaAProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub iota: Vec<Fr>,
}

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
    let mut eq1 = calculate_evaluations_over_boolean_hypercube_for_eq(&r1);
    let mut eq2 = calculate_evaluations_over_boolean_hypercube_for_eq(&r2);
    let instances = 1 << (num_vars - 6);
    let mut a = a.chunks_exact(instances).map(|x| to_poly_xor_base_multi(x)).collect::<Vec<_>>();

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
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();

        for i in 0..ea0.len() {
            for j in 0..a.len() {
                // Evaluation at 0
                p0 += beta_a[j] * ea0[i] * a[j].0[i] + beta_b[j] * eb0[i] * a[j].0[i];

                // Evaluation at ∞
                p2 += beta_a[j] * (ea1[i] - ea0[i]) * (a[j].1[i] - a[j].0[i])
                    + beta_b[j] * (eb1[i] - eb0[i]) * (a[j].1[i] - a[j].0[i]);
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
        eq_a = update(eq_a, r);
        eq_b = update(eq_b, r);
        for j in 0..aij.len() {
            // TODO: unnecessary allocation
            aij[j] = update(&mut aij[j], r).to_vec();
        }
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
        sum,
        r: rs,
        iota: subclaims,
    }
}

#[cfg(test)]
mod test {
    use crate::reference::{ROUND_CONSTANTS, keccak_round, STATE};
    use crate::sumcheck::theta_a::prove_theta_a;
    use crate::sumcheck::util::{eval_mle, to_poly_xor_base, to_poly_xor_base_multi};
    use crate::transcript::Prover;
    use ark_bn254::Fr;

    #[test]
    fn theta_a_no_recursion() {
        let num_vars = 7; // two instances
        let instances = 1usize << (num_vars - 6);

        let mut data = (0..(instances * STATE)).map(|i| i as u64).collect::<Vec<_>>();
        let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

        let mut prover = Prover::new();
        let alpha_a = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
        let alpha_b = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();

        let beta_a = (0..STATE).map(|_| prover.read()).collect::<Vec<_>>();
        let beta_b = (0..STATE).map(|_| prover.read()).collect::<Vec<_>>();

        let result = state
            .a
            .chunks_exact(instances)
            .map(|x| to_poly_xor_base_multi(x))
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
