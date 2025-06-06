use ark_bn254::Fr;
use ark_ff::Zero;
use itertools::izip;

use crate::{sumcheck::util::{update, xor, HALF}, transcript::Prover};

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
) -> (Fr, Vec<Fr>) {
    assert_eq!(e.len(), 1 << size);
    assert_eq!(a.len(), 1 << size);
    assert_eq!(b.len(), 1 << size);
    assert_eq!(c.len(), 1 << size);

    let beta_m2 = - beta_00 - beta_00;

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
        let p2 = HALF * (sum + pem1 - p0 - p0 - p0);
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
    assert_eq!(e[0] * (beta_00 * xor(a[0], b[0]) + c[0]), sum);
    (sum, rs)
}
