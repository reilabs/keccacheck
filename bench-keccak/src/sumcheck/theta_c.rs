use ark_bn254::Fr;
use ark_ff::{One, Zero};
use crate::sumcheck::rho::derive_rot_evaluations_from_eq;
use crate::sumcheck::util::{calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly_xor_base, update, HALF};
use crate::transcript::Prover;

pub struct ThetaCProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub a: Vec<Fr>,
}

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
    let mut a = a.iter().map(|x| to_poly_xor_base(*x)).collect::<Vec<_>>();

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

    todo!();

    // let proof = prove_sumcheck_theta_d(transcript, num_vars, beta, &mut eq, &mut cs, &mut rot_c, sum);
    //
    // proof
}
//
// pub fn prove_sumcheck_theta_d(
//     transcript: &mut Prover,
//     size: usize,
//     beta: &[Fr],
//     mut eq:  &mut [Fr],
//     cs: &mut Vec<Vec<Fr>>,
//     rot_cs: &mut Vec<Vec<Fr>>,
//     mut sum: Fr,
// ) -> ThetaDProof {
//     #[cfg(debug_assertions)]
//     {
//         assert_eq!(eq.len(), 1 << size);
//         assert_eq!(cs.len(), rot_cs.len());
//         cs.iter().for_each(|d| {
//             assert_eq!(d.len(), 1 << size);
//         });
//         rot_cs.iter().for_each(|ai| {
//             assert_eq!(ai.len(), 1 << size);
//         });
//     }
//
//     let mut rs = Vec::with_capacity(size);
//     for _ in 0..size {
//         // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2 + p3 ⋅ x^3
//         let mut p0 = Fr::zero();
//         let mut pem1 = Fr::zero();
//         let mut p3 = Fr::zero();
//
//         let (e0, e1) = eq.split_at(eq.len() / 2);
//         let c = cs
//             .iter()
//             .map(|x| x.split_at(x.len() / 2))
//             .collect::<Vec<_>>();
//         let rot_c = rot_cs
//             .iter()
//             .map(|x| x.split_at(x.len() / 2))
//             .collect::<Vec<_>>();
//
//         for i in 0..c[0].0.len() {
//             for j in 0..c.len() {
//                 // Evaluation at 0
//                 p0 += beta[j] * e0[i] * c[(j+4)%5].0[i] * rot_c[(j+1)%5].0[i];
//
//                 // Evaluation at -1
//                 pem1 += beta[j] * (e0[i] + e0[i] - e1[i]) * (c[(j+4)%5].0[i] + c[(j+4)%5].0[i] - c[(j+4)%5].1[i]) * (rot_c[(j+1)%5].0[i] + rot_c[(j+1)%5].0[i] - rot_c[(j+1)%5].1[i]);
//
//                 // Evaluation at ∞
//                 p3 += beta[j] * (e1[i] - e0[i]) * (c[(j+4)%5].1[i] - c[(j+4)%5].0[i]) * (rot_c[(j+1)%5].1[i] - rot_c[(j+1)%5].0[i]);
//             }
//         }
//
//         // Compute p1 and p2 from
//         //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3
//         //  p(-1) = p0 - p1 + p2 - p3
//         let p2 = HALF * (sum + pem1 - p0) - p0;
//         let p1 = sum - p0 - p0 - p3 - p2;
//         assert_eq!(sum, p0 + p0 + p1 + p2 + p3);
//         assert_eq!(pem1, p0 - p1 + p2 - p3);
//
//         transcript.write(p1);
//         transcript.write(p2);
//         transcript.write(p3);
//
//         let r = transcript.read();
//         rs.push(r);
//         // TODO: Fold update into evaluation loop.
//         eq = update(eq, r);
//         for j in 0..cs.len() {
//             // TODO: unnecessary allocation
//             cs[j] = update(&mut cs[j], r).to_vec();
//             rot_cs[j] = update(&mut rot_cs[j], r).to_vec();
//         }
//
//         // sum = p(r)
//         sum = p0 + r * (p1 + r * (p2 + r * p3));
//     }
//
//     let mut c_subclaims = Vec::with_capacity(cs.len());
//     for j in 0..cs.len() {
//         transcript.write(cs[j][0]);
//         c_subclaims.push(cs[j][0]);
//     }
//     let mut rot_c_subclaims = Vec::with_capacity(rot_cs.len());
//     for j in 0..rot_cs.len() {
//         transcript.write(rot_cs[j][0]);
//         rot_c_subclaims.push(rot_cs[j][0]);
//     }
//
//     // check result
//     #[cfg(debug_assertions)]
//     {
//         let mut checksum = Fr::zero();
//         for j in 0..cs.len() {
//             checksum += beta[j] * eq[0] * cs[(j+4)%5][0] * rot_cs[(j+1)%5][0];
//         }
//         assert_eq!(sum, checksum);
//     }
//
//     ThetaDProof {
//         sum,
//         r: rs,
//         c: c_subclaims,
//         rot_c: rot_c_subclaims,
//     }
// }

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_ff::{One, Zero};
    use crate::reference::{keccak_round, ROUND_CONSTANTS};
    use crate::sumcheck::rho::{calculate_evaluations_over_boolean_hypercube_for_rot, derive_rot_evaluations_from_eq};
    use crate::sumcheck::theta_c::prove_theta_c;
    use crate::sumcheck::theta_d::prove_theta_d;
    use crate::sumcheck::util::{calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly_xor_base};
    use crate::transcript::Prover;

    #[test]
    fn theta_c_no_recursion() {
        let input = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        ];
        let mut buf = input;
        let state = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

        let num_vars = 6; // a single u64, one instance

        let mut prover = Prover::new();
        let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
        let beta_c = (0..5).map(|_| prover.read()).collect::<Vec<_>>();
        let beta_rot_c = (0..5).map(|_| prover.read()).collect::<Vec<_>>();

        let theta_c = state.c.iter().map(|x| to_poly_xor_base(*x)).collect::<Vec<_>>();
        let theta_rot_c = state.c.iter().map(|x| to_poly_xor_base(x.rotate_left(1))).collect::<Vec<_>>();

        // TODO: implement sumcheck

        let mut real_theta_c_sum = Fr::zero();
        for i in 0..5 {
            // println!("c[{i}] = {}", beta_c[i] * eval_mle(&theta_c[i], &alpha));
            // println!("rot_c[{i}] = {}", beta_rot_c[i] * eval_mle(&theta_rot_c[i], &alpha));
            real_theta_c_sum += beta_c[i] * eval_mle(&theta_c[i], &alpha) + beta_rot_c[i] * eval_mle(&theta_rot_c[i], &alpha);
        }

        println!("real_theta_c_sum: {}", real_theta_c_sum);

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