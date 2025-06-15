use crate::sumcheck::util::{HALF, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly_xor_base, update, to_poly_xor_base_multi};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::Zero;

pub struct ThetaDProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub c: Vec<Fr>,
    pub rot_c: Vec<Fr>,
}

pub fn prove_theta_d(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta: &[Fr],
    c: &[u64],
    sum: Fr,
) -> ThetaDProof {
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);

    let instances = 1 << (num_vars - 6);

    let mut cs = c.chunks_exact(instances).map(|x| to_poly_xor_base_multi(x)).collect::<Vec<_>>();
    let mut rot_c = c.chunks_exact(instances)
        .map(|x| to_poly_xor_base_multi(&x.iter().map(|y| y.rotate_left(1)).collect::<Vec<_>>()))
        .collect::<Vec<_>>();

    #[cfg(debug_assertions)]
    {
        let mut c_sum = Fr::zero();
        for j in 0..cs.len() {
            for x in 0..(1 << num_vars) {
                c_sum += beta[j] * eq[x] * cs[(j + 4) % 5][x] * rot_c[(j + 1) % 5][x];
            }
        }
        assert_eq!(c_sum, sum);
    }

    let proof = prove_sumcheck_theta_d(
        transcript, num_vars, beta, &mut eq, &mut cs, &mut rot_c, sum,
    );

    proof
}

pub fn prove_sumcheck_theta_d(
    transcript: &mut Prover,
    size: usize,
    beta: &[Fr],
    mut eq: &mut [Fr],
    cs: &mut Vec<Vec<Fr>>,
    rot_cs: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> ThetaDProof {
    #[cfg(debug_assertions)]
    {
        assert_eq!(eq.len(), 1 << size);
        assert_eq!(cs.len(), rot_cs.len());
        cs.iter().for_each(|d| {
            assert_eq!(d.len(), 1 << size);
        });
        rot_cs.iter().for_each(|ai| {
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
        let c = cs
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();
        let rot_c = rot_cs
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();

        for i in 0..c[0].0.len() {
            for j in 0..c.len() {
                // Evaluation at 0
                p0 += beta[j] * e0[i] * c[(j + 4) % 5].0[i] * rot_c[(j + 1) % 5].0[i];

                // Evaluation at -1
                pem1 += beta[j]
                    * (e0[i] + e0[i] - e1[i])
                    * (c[(j + 4) % 5].0[i] + c[(j + 4) % 5].0[i] - c[(j + 4) % 5].1[i])
                    * (rot_c[(j + 1) % 5].0[i] + rot_c[(j + 1) % 5].0[i] - rot_c[(j + 1) % 5].1[i]);

                // Evaluation at ∞
                p3 += beta[j]
                    * (e1[i] - e0[i])
                    * (c[(j + 4) % 5].1[i] - c[(j + 4) % 5].0[i])
                    * (rot_c[(j + 1) % 5].1[i] - rot_c[(j + 1) % 5].0[i]);
            }
        }

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
        eq = update(eq, r);
        for j in 0..cs.len() {
            // TODO: unnecessary allocation
            cs[j] = update(&mut cs[j], r).to_vec();
            rot_cs[j] = update(&mut rot_cs[j], r).to_vec();
        }

        // sum = p(r)
        sum = p0 + r * (p1 + r * (p2 + r * p3));
    }

    let mut c_subclaims = Vec::with_capacity(cs.len());
    for j in 0..cs.len() {
        transcript.write(cs[j][0]);
        c_subclaims.push(cs[j][0]);
    }
    let mut rot_c_subclaims = Vec::with_capacity(rot_cs.len());
    for j in 0..rot_cs.len() {
        transcript.write(rot_cs[j][0]);
        rot_c_subclaims.push(rot_cs[j][0]);
    }

    // check result
    #[cfg(debug_assertions)]
    {
        let mut checksum = Fr::zero();
        for j in 0..cs.len() {
            checksum += beta[j] * eq[0] * cs[(j + 4) % 5][0] * rot_cs[(j + 1) % 5][0];
        }
        assert_eq!(sum, checksum);
    }

    ThetaDProof {
        sum,
        r: rs,
        c: c_subclaims,
        rot_c: rot_c_subclaims,
    }
}

#[cfg(test)]
mod test {
    use crate::reference::{ROUND_CONSTANTS, keccak_round, STATE};
    use crate::sumcheck::theta_d::prove_theta_d;
    use crate::sumcheck::util::{eval_mle, to_poly_xor_base, to_poly_xor_base_multi};
    use crate::transcript::Prover;
    use ark_bn254::Fr;

    #[test]
    fn theta_d_no_recursion() {
        let num_vars = 7; // two instances
        let instances = 1usize << (num_vars - 6);

        let mut data = (0..(instances * STATE)).map(|i| i as u64).collect::<Vec<_>>();
        let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

        let mut prover = Prover::new();
        let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
        let beta = (0..5).map(|_| prover.read()).collect::<Vec<_>>();

        let theta_d = state
            .d
            .chunks_exact(instances)
            .map(|x| to_poly_xor_base_multi(x))
            .collect::<Vec<_>>();
        let real_theta_d_sum: Fr = theta_d
            .iter()
            .enumerate()
            .map(|(i, poly)| beta[i] * eval_mle(poly, &alpha))
            .sum();

        prove_theta_d(
            &mut prover,
            num_vars,
            &alpha,
            &beta,
            &state.c,
            real_theta_d_sum,
        );
    }
}
