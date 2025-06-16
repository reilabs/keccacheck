use crate::reference::RHO_OFFSETS;
use crate::transcript::Verifier;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, MontFp, One, Zero};

#[inline(always)]
pub fn xor(a: Fr, b: Fr) -> Fr {
    let ab = a * b;
    a + b - ab - ab
}

pub const HALF: Fr =
    MontFp!("10944121435919637611123202872628637544274182200208017171849102093287904247809");

/// Target single-thread workload size for `T`.
/// Should ideally be a multiple of a cache line (64 bytes)
/// and close to the L1 cache size (32 KB).
pub const fn workload_size<T: Sized>() -> usize {
    const CACHE_SIZE: usize = 1 << 15;
    CACHE_SIZE / size_of::<T>()
}

/// List of evaluations for eq(r, x) over the boolean hypercube
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(r: &[Fr]) -> Vec<Fr> {
    let mut result = vec![Fr::zero(); 1 << r.len()];
    eval_eq(r, &mut result, Fr::one());
    result
}

/// List of evaluations for rot_i(r, x) over the boolean hypercube
pub fn calculate_evaluations_over_boolean_hypercube_for_rot(r: &[Fr], i: usize) -> Vec<Fr> {
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(r);
    derive_rot_evaluations_from_eq(&eq, RHO_OFFSETS[i] as usize)
}

pub fn derive_rot_evaluations_from_eq(eq: &[Fr], size: usize) -> Vec<Fr> {
    let mut result = vec![Fr::zero(); eq.len()];
    let instances = eq.len() / 64;
    for instance in 0..instances {
        for i in 0..64 {
            // Shift only 6 last variables (u64)
            result[instance * 64 + i] = eq[instance * 64 + (i + size) % 64];
            // println!("translating {} into {}", instance * 64 + i, instance * 64 + (i + size) % 64);
        }
    }
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

pub fn to_poly(x: &[u64]) -> Vec<Fr> {
    let mut res = Vec::with_capacity(x.len() * 64);
    for el in x {
        let mut k = 1;
        for _ in 0..64 {
            if *el & k > 0 {
                res.push(Fr::ONE);
            } else {
                res.push(Fr::ZERO);
            }
            k <<= 1;
        }
    }
    res
}

// low bits are elements, high bits are instances
pub fn to_poly_xor_base(x: &[u64]) -> Vec<Fr> {
    let mut res = Vec::with_capacity(x.len() * 64);
    for el in x {
        let mut k = 1;
        for _ in 0..64 {
            if *el & k > 0 {
                res.push(-Fr::ONE);
            } else {
                res.push(Fr::ONE);
            }
            k <<= 1;
        }
    }
    res
}

/// Updates f(x, x') -> f(r, x') and returns f
pub fn update(f: &mut [Fr], r: Fr) -> &mut [Fr] {
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
        let p: [Fr; N] = std::array::from_fn(|_| transcript.read());
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
        coefficients[0]
    }
}

pub fn eq(a: &[Fr], b: &[Fr]) -> Fr {
    a.into_iter().zip(b).map(|(&x, &y)| {
        x * y + (Fr::one() - x) * (Fr::one() - y)
    }).product::<Fr>()
}

pub fn rot(n: usize, a: &[Fr], b: &[Fr]) -> Fr {
    let len = a.len();
    let prefix = len - 6;

    let r = calculate_evaluations_over_boolean_hypercube_for_rot(&a[prefix..len], 1);
    let result = eval_mle(&r, &b[prefix..len]);
    result * a.into_iter().take(prefix).zip(b.into_iter().take(prefix)).map(|(&x, &y)| {
        x * y + (Fr::one() - x) * (Fr::one() - y)
    }).product::<Fr>()
}


#[inline(always)]
pub fn add_col(j: usize, add: usize) -> usize {
    let col = j % 5;
    let row = j - col;
    (col + add) % 5 + row
}
