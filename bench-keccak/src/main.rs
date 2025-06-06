use core::num;

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp, One, Zero};
use itertools::izip;

use crate::transcript::{Prover, Verifier};

mod poseidon;
mod transcript;

pub fn keccak_round(a: &mut [u64], rc: u64) {
    assert_eq!(a.len(), 25);
    // // Iota
    a[0] ^= rc;
}

pub const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

pub const _RHO_OFFSETS: [u32; 24] = [
    1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const HALF: Fr =
    MontFp!("10944121435919637611123202872628637544274182200208017171849102093287904247809");

/// Target single-thread workload size for `T`.
/// Should ideally be a multiple of a cache line (64 bytes)
/// and close to the L1 cache size (32 KB).
pub const fn workload_size<T: Sized>() -> usize {
    const CACHE_SIZE: usize = 1 << 15;
    CACHE_SIZE / size_of::<T>()
}

/// List of evaluations for eq(r, x) over the boolean hypercube
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(
    r: &[Fr],
) -> Vec<Fr> {
    let mut result = vec![Fr::zero(); 1 << r.len()];
    eval_eq(r, &mut result, Fr::one());
    result
}

/// Evaluates the equality polynomial recursively.
fn eval_eq(eval: &[Fr], out: &mut [Fr], scalar: Fr) {
    debug_assert_eq!(out.len(), 1 << eval.len());
    let size = out.len();
    if let Some((&x, tail)) = eval.split_first() {
        let (o0, o1) = out.split_at_mut(out.len() / 2);
        let s1 = scalar * x;
        let s0 = scalar - s1;
        if size > workload_size::<Fr>() {
            rayon::join(|| eval_eq(tail, o0, s0), || eval_eq(tail, o1, s1));
        } else {
            eval_eq(tail, o0, s0);
            eval_eq(tail, o1, s1);
        }
    } else {
        out[0] += scalar;
    }
}

fn to_poly(x: u64) -> Vec<Fr> {
    let mut res = Vec::with_capacity(64);
    let mut k = 1;
    for _ in 0..64 {
        if x & k == 1 {
            res.push(Fr::ONE);
        } else {
            res.push(Fr::ZERO);
        }
        k <<= 1;
    }
    res
}

#[inline(always)]
fn xor(a: Fr, b: Fr) -> Fr {
    let ab = a * b;
    a + b - ab - ab
}

fn main() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut output = input.clone();
    keccak_round(&mut output, ROUND_CONSTANTS[0]);

    println!("inp {input:?}");
    println!("out {output:?}");

    let numvars = 6; // a single u64, one instance

    // TODO: we should use the output somewhere!

    let mut prover = Prover::new();
    let alpha = (0..numvars).map(|_| prover.read()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    // println!("alpha: {alpha:?}");
    // println!("beta: {beta:?}");

    // run sumcheck on $\sum_k eq(alpha, k) ⋅ [\beta_00 ⋅ (\chi00(k) xor RC(k)) + \sum_ij \beta_ij\chi_ij(k)]
    // we have 4 polynomials:
    // - eq(\alpha, k)
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    // - \chi_{00}(k)
    let chi_00 = to_poly(input[0]);
    // - RC(k)
    let rc = to_poly(ROUND_CONSTANTS[0]);
    // - \sum_{ij} \beta_{ij}\chi_{ij}(k) where (i, j) != (0, 0)
    let mut chi_rlc = vec![Fr::ZERO; 1<<numvars];
    for i in 1..25 {
        let poly = to_poly(input[i]);
        for j in 0..(1<<numvars) {
            chi_rlc[j] += beta[i] * poly[j];
        }
    }

    let sum = izip!(&eq, &chi_00, &rc, &chi_rlc)
        .map(|(&a, &b, &c, &d)| {
            a * ((beta[0] * xor(b, c)) + d)
        })
        .sum();

    // Prove
    prover.write(sum);
    let (pe, prs) = {
        let mut eq = eq.clone();
        let mut chi_00 = chi_00.clone();
        let mut rc = rc.clone();
        let mut chi_rlc = chi_rlc.clone();
        prove_sumcheck_iota(&mut prover, numvars, beta[0], &mut eq, &mut chi_00, &mut rc, &mut chi_rlc, sum)
    };
    let proof = prover.finish();
    let e_eq = eval_mle(&eq, &prs); // TODO: can evaluate eq faster
    let e_chi_00 = eval_mle(&chi_00, &prs);
    let e_rc = eval_mle(&rc, &prs);
    let e_chi_rlc = eval_mle(&chi_rlc, &prs);
    assert_eq!(e_eq * (beta[0] * xor(e_chi_00, e_rc) + e_chi_rlc), pe);

    // Verify
    let mut verifier = Verifier::new(&proof);

    let alpha = (0..numvars).map(|_| verifier.generate()).collect::<Vec<_>>();
    let beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    let vs = verifier.read();
    assert_eq!(vs, sum);
    let (ve, vrs) = verify_sumcheck::<3>(&mut verifier, numvars, vs);
    
    // Verify last step (TODO: verifier needs to combine sublaims and continue recursively)
    // TODO: do the same work we did in the prover
    assert_eq!(vrs, prs);
    assert_eq!(ve, pe);

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

/// Updates f(x, x') -> f(r, x') and returns f
fn update(f: &mut [Fr], r: Fr) -> &mut [Fr] {
    let (a, b) = f.split_at_mut(f.len() / 2);
    a.iter_mut().zip(b).for_each(|(a, b)| *a += r * (*b - *a));
    a
}

/// Verify sumcheck for $N$-degree polynomials.
/// I.e. N = 1 for linear, 2 for quadratic, etc.
pub fn verify_sumcheck<const N: usize>(
    transcript: &mut Verifier,
    size: usize,
    mut e: Fr,
) -> (Fr, Vec<Fr>) {
    let mut rs = Vec::with_capacity(size);
    for _ in 0..size {
        let p: [Fr; N] = std::array::from_fn(|_| {
            transcript.read()
        });
        // Derive p0 from e = p(0) + p(1)
        let p0 = HALF * (e - p.iter().sum::<Fr>());
        let r = transcript.generate();
        rs.push(r);
        // p(r) = p0 + p[0] ⋅ r + p[1] ⋅ r^2 + ...
        e = p0
            + r * p
                .into_iter()
                .rev()
                .reduce(|acc, p| p + r * acc)
                .expect("p not empty");
    }
    (e, rs)
}

/// Evaluates a multilinear extension at a point.
/// Uses a cache-oblivious recursive algorithm.
pub fn eval_mle(coefficients: &[Fr], eval: &[Fr]) -> Fr {
    debug_assert_eq!(coefficients.len(), 1 << eval.len());
    if let Some((&x, tail)) = eval.split_first() {
        let (c0, c1) = coefficients.split_at(coefficients.len() / 2);
        (Fr::one() - x) * eval_mle(c0, tail) + x * eval_mle(c1, tail)
    } else {
        return coefficients[0];
    }
}
