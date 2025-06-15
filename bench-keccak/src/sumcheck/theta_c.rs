use crate::sumcheck::util::{
    HALF, calculate_evaluations_over_boolean_hypercube_for_eq, derive_rot_evaluations_from_eq,
    to_poly_xor_base, update,
};
use crate::transcript::Prover;
use ark_bn254::Fr;
use ark_ff::{MontFp, One, Zero};
use tracing::instrument;
use crate::poseidon::permute_3;

pub struct ThetaCProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub a: Vec<Fr>,
}

#[instrument(skip_all)]
pub fn prove_theta_c(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta_c: &[Fr],
    beta_rot_c: &[Fr],
    a: &[u64],
    sum: Fr,
) -> ThetaCProof {
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);
    let mut rot = derive_rot_evaluations_from_eq(&eq, 1);
    let instances = 1 << (num_vars - 6);
    let mut a = a
        .chunks_exact(instances)
        .map(|x| to_poly_xor_base(x))
        .collect::<Vec<_>>();

    #[cfg(debug_assertions)]
    {
        let mut a_sum = Fr::zero();
        for j in 0..5 {
            let mut a_product = Fr::zero();
            let mut rot_product = Fr::zero();

            for x in 0..(1 << num_vars) {
                let mut product = Fr::one();
                for i in 0..5 {
                    product *= a[i * 5 + j][x];
                }
                a_product += beta_c[j] * eq[x] * product;
                rot_product += beta_rot_c[j] * rot[x] * product;
            }

            // println!("a_product: {}", a_product);
            // println!("rot_product: {}", rot_product);

            a_sum += a_product + rot_product;
        }
        assert_eq!(a_sum, sum);
    }

    let proof = prove_sumcheck_theta_c(
        transcript, num_vars, beta_c, beta_rot_c, &mut eq, &mut rot, &mut a, sum,
    );

    proof
}

pub fn prove_sumcheck_theta_c(
    transcript: &mut Prover,
    size: usize,
    beta_c: &[Fr],
    beta_rot_c: &[Fr],
    mut eq: &mut [Fr],
    mut rot: &mut [Fr],
    aij: &mut Vec<Vec<Fr>>,
    mut sum: Fr,
) -> ThetaCProof {
    #[cfg(debug_assertions)]
    {
        assert_eq!(beta_c.len(), beta_rot_c.len());
        assert_eq!(eq.len(), 1 << size);
        assert_eq!(rot.len(), 1 << size);
        assert_eq!(aij.len(), 25);
        aij.iter().for_each(|a| {
            assert_eq!(a.len(), 1 << size);
        });
    }

    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2 + p3 ⋅ x^3 + p4 ⋅ x^4 + p5 ⋅ x^5 + p6 ⋅ x^6
        let mut p0 = Fr::zero();
        let mut pem1 = Fr::zero();
        let mut pem2 = Fr::zero();
        let mut pe2 = Fr::zero();
        let mut pe3 = Fr::zero();
        let mut p6 = Fr::zero();

        let (e0, e1) = eq.split_at(eq.len() / 2);
        let (rot0, rot1) = rot.split_at(rot.len() / 2);

        let a = aij
            .iter()
            .map(|x| x.split_at(x.len() / 2))
            .collect::<Vec<_>>();

        for j in 0..5 {
            let mut p0_c = Fr::zero();
            let mut pem1_c = Fr::zero();
            let mut pem2_c = Fr::zero();
            let mut pe2_c = Fr::zero();
            let mut pe3_c = Fr::zero();
            let mut p6_c = Fr::zero();

            let mut p0_rot = Fr::zero();
            let mut pem1_rot = Fr::zero();
            let mut pem2_rot = Fr::zero();
            let mut pe2_rot = Fr::zero();
            let mut pe3_rot = Fr::zero();
            let mut p6_rot = Fr::zero();

            for i in 0..e0.len() {
                // TODO: no need to add so many times, partial results should be cached

                // Evaluation at 0
                let mut product = Fr::one();
                for k in 0..5 {
                    product *= a[k * 5 + j].0[i];
                }
                p0_c += product * e0[i];
                p0_rot += product * rot0[i];

                // Evaluation at -1
                let mut product = Fr::one();
                for k in 0..5 {
                    product *= a[k * 5 + j].0[i] + a[k * 5 + j].0[i] - a[k * 5 + j].1[i];
                }
                pem1_c += product * (e0[i] + e0[i] - e1[i]);
                pem1_rot += product * (rot0[i] + rot0[i] - rot1[i]);

                // Evaluation at -2
                let mut product = Fr::one();
                for k in 0..5 {
                    product *= a[k * 5 + j].0[i] + a[k * 5 + j].0[i] + a[k * 5 + j].0[i]
                        - a[k * 5 + j].1[i]
                        - a[k * 5 + j].1[i];
                }
                pem2_c += product * (e0[i] + e0[i] + e0[i] - e1[i] - e1[i]);
                pem2_rot += product * (rot0[i] + rot0[i] + rot0[i] - rot1[i] - rot1[i]);

                // Evaluation at 2
                let mut product = Fr::one();
                for k in 0..5 {
                    product *= a[k * 5 + j].1[i] + a[k * 5 + j].1[i] - a[k * 5 + j].0[i];
                }
                pe2_c += product * (e1[i] + e1[i] - e0[i]);
                pe2_rot += product * (rot1[i] + rot1[i] - rot0[i]);

                // Evaluation at 3
                let mut product = Fr::one();
                for k in 0..5 {
                    product *= a[k * 5 + j].1[i] + a[k * 5 + j].1[i] + a[k * 5 + j].1[i]
                        - a[k * 5 + j].0[i]
                        - a[k * 5 + j].0[i];
                }
                pe3_c += product * (e1[i] + e1[i] + e1[i] - e0[i] - e0[i]);
                pe3_rot += product * (rot1[i] + rot1[i] + rot1[i] - rot0[i] - rot0[i]);

                // Evaluation at ∞
                let mut product = Fr::one();
                for k in 0..5 {
                    product *= a[k * 5 + j].1[i] - a[k * 5 + j].0[i];
                }
                p6_c += product * (e1[i] - e0[i]);
                p6_rot += product * (rot1[i] - rot0[i]);
            }

            p0 += p0_c * beta_c[j] + p0_rot * beta_rot_c[j];
            pem1 += pem1_c * beta_c[j] + pem1_rot * beta_rot_c[j];
            pem2 += pem2_c * beta_c[j] + pem2_rot * beta_rot_c[j];
            pe2 += pe2_c * beta_c[j] + pe2_rot * beta_rot_c[j];
            pe3 += pe3_c * beta_c[j] + pe3_rot * beta_rot_c[j];
            p6 += p6_c * beta_c[j] + p6_rot * beta_rot_c[j];
        }

        // Compute p1, p2, p3, p4, p5 from
        //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3 + p4 + p5 + p6
        //  p(-1) = p0 - p1 + p2 - p3 + p4 - p5 + p6
        //  p(-2) = p0 - 2 ⋅ p1 + 4 ⋅ p2 - 8 ⋅ p3 + 16 ⋅ p4
        //  p(2) = p0 + 2 ⋅ p1 + 4 ⋅ p2 + 8 ⋅ p3 + 16 ⋅ p4
        //  p(3) = p0 + 3 ⋅ p1 + 9 ⋅ p2 + 27 ⋅ p3 + 81 ⋅ p4
        let pe1 = sum - p0;

        let add_p2_p4 = HALF * (pe1 + pem1) - p0 - p6;
        let add_p2_4p4 = (pe2 + pem2 - p0 - p0 - MontFp!("128") * p6) / MontFp!("8");
        let p4 = (add_p2_4p4 - add_p2_p4) / MontFp!("3");
        let p2 = add_p2_p4 - p4;

        assert_eq!(pe1 + pem1, (p0 + p2 + p4 + p6) * MontFp!("2"));
        assert_eq!(
            pe2 + pem2,
            MontFp!("2") * p0 + MontFp!("8") * p2 + MontFp!("32") * p4 + MontFp!("128") * p6
        );

        let add_p1_p3_p5 = HALF * (pe1 - pem1);
        let add_p1_4p3_16p5 = HALF * HALF * (pe2 - pem2);
        let add_p1_9p3_81p5 =
            (pe3 - p0 - MontFp!("9") * p2 - MontFp!("81") * p4 - MontFp!("729") * p6)
                / MontFp!("3");
        let p5 = (MontFp!("3") * add_p1_9p3_81p5 - MontFp!("8") * add_p1_4p3_16p5
            + MontFp!("5") * add_p1_p3_p5)
            / MontFp!("120");

        let add_p1_p3 = add_p1_p3_p5 - p5;
        let add_p1_4p3 = add_p1_4p3_16p5 - MontFp!("16") * p5;
        let p3 = (add_p1_4p3 - add_p1_p3) / MontFp!("3");
        let p1 = add_p1_p3 - p3;

        assert_eq!(add_p1_p3_p5, p1 + p3 + p5);
        assert_eq!(add_p1_4p3_16p5, p1 + MontFp!("4") * p3 + MontFp!("16") * p5);
        assert_eq!(add_p1_9p3_81p5, p1 + MontFp!("9") * p3 + MontFp!("81") * p5);

        assert_eq!(pe1 - pem1, (p1 + p3 + p5) * MontFp!("2"));
        assert_eq!(
            pe2 - pem2,
            MontFp!("4") * p1 + MontFp!("16") * p3 + MontFp!("64") * p5
        );

        assert_eq!(sum, p0 + p0 + p1 + p2 + p3 + p4 + p5 + p6);
        assert_eq!(pem1, p0 - p1 + p2 - p3 + p4 - p5 + p6);
        assert_eq!(
            pem2,
            p0 - MontFp!("2") * p1 + MontFp!("4") * p2 - MontFp!("8") * p3 + MontFp!("16") * p4
                - MontFp!("32") * p5
                + MontFp!("64") * p6
        );
        assert_eq!(
            pe2,
            p0 + MontFp!("2") * p1
                + MontFp!("4") * p2
                + MontFp!("8") * p3
                + MontFp!("16") * p4
                + MontFp!("32") * p5
                + MontFp!("64") * p6
        );
        assert_eq!(
            pe3,
            p0 + MontFp!("3") * p1
                + MontFp!("9") * p2
                + MontFp!("27") * p3
                + MontFp!("81") * p4
                + MontFp!("243") * p5
                + MontFp!("729") * p6
        );

        // assert_eq!(pe2, p0 - p1 + p2 - p3 + p4 - p5 + p6);
        // assert_eq!(pe3, p0 - p1 + p2 - p3 + p4 - p5 + p6);

        assert_eq!(MontFp!("3"), Fr::one() + Fr::one() + Fr::one());

        transcript.write(p1);
        transcript.write(p2);
        transcript.write(p3);
        transcript.write(p4);
        transcript.write(p5);
        transcript.write(p6);

        let r = transcript.read();
        rs.push(r);
        // TODO: Fold update into evaluation loop.
        eq = update(eq, r);
        rot = update(rot, r);
        for j in 0..aij.len() {
            // TODO: unnecessary allocation
            aij[j] = update(&mut aij[j], r).to_vec();
        }

        // sum = p(r)
        sum = p0 + r * (p1 + r * (p2 + r * (p3 + r * (p4 + r * (p5 + r * p6)))));
    }

    let mut subclaims = Vec::with_capacity(aij.len());
    for j in 0..aij.len() {
        transcript.write(aij[j][0]);
        subclaims.push(aij[j][0]);
    }

    // check result
    #[cfg(debug_assertions)]
    {
        //println!("eq {} beta {beta_c:?} rot {} beta {beta_rot_c:?} a: {:?}", eq[0], rot[0], aij);

        let mut checksum = Fr::zero();
        for j in 0..5 {
            let mut a_product = Fr::zero();
            let mut rot_product = Fr::zero();

            let mut product = Fr::one();
            for i in 0..5 {
                product *= aij[i * 5 + j][0];
            }
            a_product += beta_c[j] * eq[0] * product;
            rot_product += beta_rot_c[j] * rot[0] * product;
            checksum += a_product + rot_product;
        }
        assert_eq!(checksum, sum);
    }

    ThetaCProof {
        sum,
        r: rs,
        a: subclaims,
    }
}

#[cfg(test)]
mod test {
    use crate::reference::{COLUMNS, ROUND_CONSTANTS, STATE, keccak_round};
    use crate::sumcheck::theta_c::prove_theta_c;
    use crate::sumcheck::util::{
        calculate_evaluations_over_boolean_hypercube_for_eq,
        calculate_evaluations_over_boolean_hypercube_for_rot, derive_rot_evaluations_from_eq,
        eval_mle, to_poly_xor_base,
    };
    use crate::transcript::Prover;
    use ark_bn254::Fr;
    use ark_ff::Zero;

    #[test]
    fn theta_c_no_recursion() {
        let num_vars = 7; // two instances
        let instances = 1usize << (num_vars - 6);

        let mut data = (0..(instances * STATE))
            .map(|i| i as u64)
            .collect::<Vec<_>>();
        let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

        let mut prover = Prover::new();
        let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
        let beta_c = (0..COLUMNS).map(|_| prover.read()).collect::<Vec<_>>();
        let beta_rot_c = (0..COLUMNS).map(|_| prover.read()).collect::<Vec<_>>();

        let theta_c = state
            .c
            .chunks_exact(instances)
            .map(|x| to_poly_xor_base(x))
            .collect::<Vec<_>>();
        let theta_rot_c = state
            .c
            .chunks_exact(instances)
            .map(|x| to_poly_xor_base(&x.iter().map(|y| y.rotate_left(1)).collect::<Vec<_>>()))
            .collect::<Vec<_>>();

        assert_eq!(state.c.len(), instances * COLUMNS);
        assert_eq!(theta_c.len(), COLUMNS);

        let mut real_theta_c_sum = Fr::zero();
        for i in 0..COLUMNS {
            // println!("c[{i}] = {}", beta_c[i] * eval_mle(&theta_c[i], &alpha));
            // println!("rot_c[{i}] = {}", beta_rot_c[i] * eval_mle(&theta_rot_c[i], &alpha));
            real_theta_c_sum += beta_c[i] * eval_mle(&theta_c[i], &alpha)
                + beta_rot_c[i] * eval_mle(&theta_rot_c[i], &alpha);
        }

        // println!("real_theta_c_sum: {}", real_theta_c_sum);

        let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
        let expected_rot = calculate_evaluations_over_boolean_hypercube_for_rot(&alpha, 1);
        let rot = derive_rot_evaluations_from_eq(&eq, 1);
        assert_eq!(expected_rot, rot);

        prove_theta_c(
            &mut prover,
            num_vars,
            &alpha,
            &beta_c,
            &beta_rot_c,
            &state.a,
            real_theta_c_sum,
        );
    }
}
