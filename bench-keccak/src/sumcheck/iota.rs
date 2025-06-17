#[cfg(debug_assertions)]
use crate::sumcheck::util::eval_mle;
use crate::sumcheck::util::{calculate_evaluations_over_boolean_hypercube_for_eq, to_poly, to_poly_coeff};
use crate::{
    sumcheck::util::{HALF, update, xor},
    transcript::Prover,
};
use ark_bn254::Fr;
use ark_ff::Zero;
use rayon::prelude::*;
use tracing::instrument;

pub struct IotaProof {
    pub _sum: Fr,
    pub r: Vec<Fr>,
    pub chi_00: Fr,
    pub chi_rlc: Fr,
}

#[instrument(skip_all)]
pub fn prove_iota(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta: &[Fr],
    chi: &[u64],
    sum: Fr,
    rc: u64,
) -> IotaProof {
    let instances = 1 << (num_vars - 6);

    let mut chi_poly = (0..25).into_par_iter().map(|el| {
        let slice = &chi[(el * instances)..(el * instances + instances)];
        if el == 0 {
            to_poly(slice)
        } else {
            to_poly_coeff(slice, beta[el])
        }
    }).collect::<Vec<_>>();

    let mut chi_rlc = vec![Fr::zero(); 1 << num_vars];

    let ((mut eq, mut rc_poly), mut chi_rlc) = rayon::join(
        || {
            rayon::join(
                || calculate_evaluations_over_boolean_hypercube_for_eq(r),
                || to_poly(&vec![rc; instances]),
            )
        },
        || {
            let chunk_size = 8192;
            chi_rlc.par_chunks_mut(chunk_size).enumerate().for_each(|(chunk, slice)| {
                // iterating from 1 to skip the first state element (i, j) = (0, 0)
                for el in 1..25 {
                    for (x, v) in slice.iter_mut().enumerate() {
                        let i = chunk * chunk_size + x;
                        *v += chi_poly[el][i];
                    }
                }
            });
            chi_rlc
        },
    );

    #[cfg(debug_assertions)]
    {
        let mut c_sum = Fr::zero();
        for x in 0..(1 << num_vars) {
            c_sum += eq[x] * (beta[0] * xor(chi_poly[0][x], rc_poly[x]) + chi_rlc[x]);
        }
        assert_eq!(c_sum, sum);
    }

    let proof = prove_sumcheck_iota(
        transcript,
        num_vars,
        beta[0],
        &mut eq,
        &mut chi_poly[0],
        &mut rc_poly,
        &mut chi_rlc,
        sum,
    );

    #[cfg(debug_assertions)]
    {
        // sumcheck consumed all polynomials. create again
        let eq = calculate_evaluations_over_boolean_hypercube_for_eq(r);
        let chi_00 = to_poly(&chi[0..instances]);
        let rc = to_poly(&vec![rc; instances]);
        let mut chi_rlc = vec![Fr::zero(); 1 << num_vars];
        for el in 1..25 {
            let slice = &chi[(el * instances)..(el * instances + instances)];
            let poly = to_poly(slice);
            for x in 0..(1 << num_vars) {
                chi_rlc[x] += beta[el] * poly[x];
            }
        }

        let e_eq = eval_mle(&eq, &proof.r);
        let e_chi_00 = eval_mle(&chi_00, &proof.r);
        let e_rc = eval_mle(&rc, &proof.r);
        let e_chi_rlc = eval_mle(&chi_rlc, &proof.r);
        assert_eq!(proof.chi_00, e_chi_00);
        assert_eq!(proof.chi_rlc, e_chi_rlc);
        assert_eq!(
            e_eq * (beta[0] * xor(e_chi_00, e_rc) + e_chi_rlc),
            proof._sum
        );
    }

    proof
}

/// Sumcheck for $\sum_x e(x) ⋅ (\beta ⋅ xor(a(x), b(x)) + c(x))$.
/// Returns $(e, r)$ for reduced claim $e = e(r) ⋅ (\beta ⋅ xor(a(r), b(r)) + c(r))$.
pub fn prove_sumcheck_iota(
    transcript: &mut Prover,
    size: usize,
    beta_00: Fr,
    mut e: &mut [Fr],
    mut a: &mut [Fr],
    mut b: &mut [Fr],
    mut c: &mut [Fr],
    mut sum: Fr,
) -> IotaProof {
    assert_eq!(e.len(), 1 << size);
    assert_eq!(a.len(), 1 << size);
    assert_eq!(b.len(), 1 << size);
    assert_eq!(c.len(), 1 << size);

    let beta_m2 = -beta_00 - beta_00;

    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        // p(x) = p0 + p1 ⋅ x + p2 ⋅ x^2 + p3 ⋅ x^3
        let mut p0 = Fr::zero();
        let mut pem1 = Fr::zero();
        let mut p3 = Fr::zero();
        let (e0, e1) = e.split_at(e.len() / 2);
        let (a0, a1) = a.split_at(a.len() / 2);
        let (b0, b1) = b.split_at(b.len() / 2);
        let (c0, c1) = c.split_at(c.len() / 2);

        // TODO: this should be parallelized ProveKit style

        // (0..e0.len()).into_par_iter().chunks(1024).map(|j| {
        //
        // }).reduce_with(|a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2))
        //     .unwrap();

        let chunk = 1024;

        let (p0t, pem1t, p3t) = e0.par_chunks(chunk).zip(e1.par_chunks(chunk)).zip(
            a0.par_chunks(chunk).zip(a1.par_chunks(chunk))
        ).zip(
        b0.par_chunks(chunk).zip(b1.par_chunks(chunk)).zip(
            c0.par_chunks(chunk).zip(c1.par_chunks(chunk))
        ))
        .map(|x| {
            let (((e0, e1), (a0, a1)), ((b0, b1), (c0, c1))) = x;
            let mut p0 = Fr::zero();
            let mut pem1 = Fr::zero();
            let mut p3 = Fr::zero();
            for i in 0..e0.len() {
                // Evaluation at 0
                p0 += e0[i] * (beta_00 * xor(a0[i], b[i]) + c0[i]);
                // Evaluation at -1
                let eem1 = e0[i] + e0[i] - e1[i]; // e(-1)
                let aem1 = a0[i] + a0[i] - a1[i]; // a(-1)
                let bem1 = b0[i] + b0[i] - b1[i]; // b(-1)
                let cem1 = c0[i] + c0[i] - c1[i]; // c(-1)
                pem1 += eem1 * (beta_00 * xor(aem1, bem1) + cem1);
                // Evaluation at ∞
                p3 += beta_m2 * (e1[i] - e0[i]) * (a1[i] - a0[i]) * (b1[i] - b0[i]);
            }
            (p0, pem1, p3)
        })
        .reduce_with(|a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2))
        .unwrap();

        p0 += p0t;
        pem1 += pem1t;
        p3 += p3t;

        // Compute p1 and p2 from
        //  p(0) + p(1) = 2 ⋅ p0 + p1 + p2 + p3
        //  p(-1) = p0 - p1 + p2 - p3
        let p2 = HALF * (sum + pem1 - p0) - p0;
        let p1 = sum - p0 - p0 - p3 - p2;
        assert_eq!(p0 + p0 + p1 + p2 + p3, sum);
        transcript.write(p1);
        transcript.write(p2);
        transcript.write(p3);

        let r = transcript.read();
        rs.push(r);
        // TODO: Fold update into evaluation loop.
        ((e, a), (b, c)) = rayon::join(
            || rayon::join(|| update(e, r), || update(a, r)),
            || rayon::join(|| update(b, r), || update(c, r)),
        );
        // sum = p(r)
        sum = p0 + r * (p1 + r * (p2 + r * p3));
    }
    transcript.write(a[0]); // chi_00(r)
    transcript.write(c[0]); // \sum_{ij} \beta_{ij} ⋅ chi_{ij}
    assert_eq!(e[0] * (beta_00 * xor(a[0], b[0]) + c[0]), sum);

    IotaProof {
        _sum: sum,
        r: rs,
        chi_00: a[0],
        chi_rlc: c[0],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference::{ROUND_CONSTANTS, STATE, keccak_round};
    use crate::sumcheck::util::to_poly;
    use ark_ff::One;

    #[test]
    fn iota_no_recursion() {
        let num_vars = 7; // two instances
        let instances = 1usize << (num_vars - 6);

        let mut data = (0..(instances * STATE))
            .map(|i| i as u64)
            .collect::<Vec<_>>();
        let state = keccak_round(&mut data, 0);

        let mut prover = Prover::new();
        let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
        let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

        let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
        let chi_00 = to_poly(&state.pi_chi[0..instances]);
        let rc = to_poly(&vec![ROUND_CONSTANTS[0]; instances]);
        let mut chi_rlc = vec![Fr::zero(); 1 << num_vars];
        for el in 1..25 {
            // iterating from 1 to skip the first state element (i, j) = (0, 0)
            let slice = &state.pi_chi[(el * instances)..(el * instances + instances)];
            let poly = to_poly(slice);
            for x in 0..(1 << num_vars) {
                chi_rlc[x] += beta[el] * poly[x];
            }
        }
        let chi = state
            .pi_chi
            .chunks_exact(instances)
            .map(to_poly)
            .collect::<Vec<_>>();
        let iota = state
            .iota
            .chunks_exact(instances)
            .map(to_poly)
            .collect::<Vec<_>>();

        let real_iota_sum: Fr = iota
            .iter()
            .enumerate()
            .map(|(i, poly)| beta[i] * eval_mle(poly, &alpha))
            .sum();

        let (pe, prs) = {
            let mut eq = eq.clone();
            let mut chi_00 = chi_00.clone();
            let mut rc = rc.clone();
            let mut chi_rlc = chi_rlc.clone();
            let proof = prove_sumcheck_iota(
                &mut prover,
                num_vars,
                beta[0],
                &mut eq,
                &mut chi_00,
                &mut rc,
                &mut chi_rlc,
                real_iota_sum,
            );
            (proof._sum, proof.r)
        };
        let e_eq = eval_mle(&eq, &prs); // TODO: can evaluate eq faster
        let e_chi_00 = eval_mle(&chi_00, &prs);
        let e_rc = eval_mle(&rc, &prs);
        let e_chi_rlc = eval_mle(&chi_rlc, &prs);
        assert_eq!(e_eq * (beta[0] * xor(e_chi_00, e_rc) + e_chi_rlc), pe);

        println!();

        for step in 0..num_vars {
            let mut p = [Fr::zero(); 4];
            for i in 0..iota.len() {
                for k in 0..(1 << (num_vars - step - 1)) {
                    let under_sum = to_poly(&[k])[0..(num_vars - step - 1)].to_vec();
                    let mut eval = vec![Fr::zero(); step + 1];
                    for k in 0..step {
                        eval[k] = prs[k];
                    }
                    eval[step] = Fr::zero();
                    eval.extend_from_slice(&under_sum);
                    assert_eq!(eval.len(), num_vars);
                    // println!("eval st {step} i {i} @ 0: {eval:?}");

                    let val = if i == 0 {
                        xor(eval_mle(&chi[i], &eval), eval_mle(&rc, &eval))
                    } else {
                        eval_mle(&chi[i], &eval)
                    };
                    p[0] += beta[i] * eval_mle(&eq, &eval) * val;

                    eval[step] = -Fr::one();
                    let val = if i == 0 {
                        xor(eval_mle(&chi[i], &eval), eval_mle(&rc, &eval))
                    } else {
                        eval_mle(&chi[i], &eval)
                    };
                    p[1] += beta[i] * eval_mle(&eq, &eval) * val;
                }
            }
            println!("step {step} v(0) = {}", p[0]);
            println!("step {step} v(-1) = {}", p[1]);
        }
    }
}
