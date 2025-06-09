use ark_bn254::Fr;
use ark_ff::Zero;
use itertools::izip;

use crate::{
    sumcheck::util::{HALF, update, xor},
    transcript::Prover,
};
use crate::reference::ROUND_CONSTANTS;
use crate::sumcheck::util::{calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly};

pub struct IotaProof {
    pub sum: Fr,
    pub r: Vec<Fr>,
    pub chi_00: Fr,
    pub chi_rlc: Fr,
}

pub fn prove_iota(
    transcript: &mut Prover,
    num_vars: usize,
    r: &[Fr],
    beta: &[Fr],
    chi: &[u64],
    sum: Fr,
) -> IotaProof {
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);
    let mut chi_00 = to_poly(chi[0]);
    let mut rc = to_poly(ROUND_CONSTANTS[0]);
    let mut chi_rlc = vec![Fr::zero(); 1 << num_vars];
    // iterating from 1 to skip the first state element (i, j) = (0, 0)
    for el in 1..25 {
        let poly = to_poly(chi[el]);
        for x in 0..(1 << num_vars) {
            chi_rlc[x] += beta[el] * poly[x];
        }
    }

    let proof = prove_sumcheck_iota(
        transcript,
        num_vars,
        beta[0],
        &mut eq,
        &mut chi_00,
        &mut rc,
        &mut chi_rlc,
        sum,
    );

    #[cfg(debug_assertions)]
    {
        // sumcheck consumed all polynomials. create again
        let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&r);
        let chi_00 = to_poly(chi[0]);
        let rc = to_poly(ROUND_CONSTANTS[0]);
        let mut chi_rlc = vec![Fr::zero(); 1 << num_vars];
        for el in 1..25 {
            let poly = to_poly(chi[el]);
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
        assert_eq!(e_eq * (beta[0] * xor(e_chi_00, e_rc) + e_chi_rlc), proof.sum);
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
        izip!(
            e0.iter().zip(e1),
            a0.iter().zip(a1),
            b0.iter().zip(b1),
            c0.iter().zip(c1)
        )
        .for_each(|(e, a, b, c)| {
            // Evaluation at 0
            p0 += *e.0 * (beta_00 * xor(*a.0, *b.0) + c.0);
            // Evaluation at -1
            let eem1 = e.0 + e.0 - e.1; // e(-1)
            let aem1 = a.0 + a.0 - a.1; // a(-1)
            let bem1 = b.0 + b.0 - b.1; // b(-1)
            let cem1 = c.0 + c.0 - c.1; // c(-1)
            pem1 += eem1 * (beta_00 * xor(aem1, bem1) + cem1);
            // Evaluation at ∞
            p3 += beta_m2 * (e.1 - e.0) * (a.1 - a.0) * (b.1 - b.0);
        });
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
        e = update(e, r);
        a = update(a, r);
        b = update(b, r);
        c = update(c, r);
        // sum = p(r)
        sum = p0 + r * (p1 + r * (p2 + r * p3));
    }
    transcript.write(a[0]); // chi_00(r)
    transcript.write(c[0]); // \sum_{ij} \beta_{ij} ⋅ chi_{ij}
    assert_eq!(e[0] * (beta_00 * xor(a[0], b[0]) + c[0]), sum);

    IotaProof {
        sum,
        r: rs,
        chi_00: a[0],
        chi_rlc: c[0],
    }
}
