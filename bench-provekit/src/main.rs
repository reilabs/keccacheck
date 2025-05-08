// NOTICE: sumcheck implementation copied from https://github.com/worldfnd/ProveKit

use ark_ff::{BigInt, Field, Fp256, MontBackend};
use ark_ff_macros::MontConfig;
use ark_std::UniformRand;
use ark_std::rand::thread_rng;
use ruint::aliases::U256;
use ruint::uint;
use spongefish::codecs::arkworks_algebra::{FieldToUnitSerialize, UnitToField};
use std::mem::MaybeUninit;
use spongefish::DomainSeparator;
use tracing::{event, Level};
use {
    ark_std::{One, Zero},
    rayon::iter::{IndexedParallelIterator as _, IntoParallelRefIterator, ParallelIterator as _},
    spongefish::codecs::arkworks_algebra::FieldDomainSeparator,
    std::array,
    tracing::instrument,
};

#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "5"]
pub struct BN254Config;
pub type FieldElement = Fp256<MontBackend<BN254Config, 4>>;

/// Target single-thread workload size for `T`.
/// Should ideally be a multiple of a cache line (64 bytes)
/// and close to the L1 cache size (32 KB).
pub const fn workload_size<T: Sized>() -> usize {
    const CACHE_SIZE: usize = 1 << 15;
    CACHE_SIZE / size_of::<T>()
}

/// Unzip a [[(T,T); N]; M] into ([[T; N]; M],[[T; N]; M]) using move semantics
// TODO: Cleanup when <https://github.com/rust-lang/rust/issues/96097> lands
#[allow(unsafe_code)] // Required for `MaybeUninit`
fn unzip_double_array<T: Sized, const N: usize, const M: usize>(
    input: [[(T, T); N]; M],
) -> ([[T; N]; M], [[T; N]; M]) {
    // Create uninitialized memory for the output arrays
    let mut left: [[MaybeUninit<T>; N]; M] = [const { [const { MaybeUninit::uninit() }; N] }; M];
    let mut right: [[MaybeUninit<T>; N]; M] = [const { [const { MaybeUninit::uninit() }; N] }; M];

    // Move results to output arrays
    for (i, a) in input.into_iter().enumerate() {
        for (j, (l, r)) in a.into_iter().enumerate() {
            left[i][j] = MaybeUninit::new(l);
            right[i][j] = MaybeUninit::new(r);
        }
    }

    // Convert the arrays of MaybeUninit into fully initialized arrays
    // Safety: All the elements have been initialized above
    let left = left.map(|a| a.map(|u| unsafe { u.assume_init() }));
    let right = right.map(|a| a.map(|u| unsafe { u.assume_init() }));
    (left, right)
}

/// Compute the sum of a vector valued function over the boolean hypercube in
/// the leading variable.
// TODO: Figure out a way to also half the mles on folding
pub fn sumcheck_fold_map_reduce<const N: usize, const M: usize>(
    mles: [&mut [FieldElement]; N],
    fold: Option<FieldElement>,
    map: impl Fn([(FieldElement, FieldElement); N]) -> [FieldElement; M] + Send + Sync + Copy,
) -> [FieldElement; M] {
    let size = mles[0].len();
    assert!(size.is_power_of_two());
    assert!(size >= 2);
    assert!(mles.iter().all(|mle| mle.len() == size));

    if let Some(fold) = fold {
        assert!(size >= 4);
        let slices = mles.map(|mle| {
            let (p0, tail) = mle.split_at_mut(size / 4);
            let (p1, tail) = tail.split_at_mut(size / 4);
            let (p2, p3) = tail.split_at_mut(size / 4);
            [p0, p1, p2, p3]
        });
        sumcheck_fold_map_reduce_inner::<N, M>(slices, fold, map)
    } else {
        let slices = mles.map(|mle| mle.split_at(size / 2));
        sumcheck_map_reduce_inner::<N, M>(slices, map)
    }
}

fn sumcheck_map_reduce_inner<const N: usize, const M: usize>(
    mles: [(&[FieldElement], &[FieldElement]); N],
    map: impl Fn([(FieldElement, FieldElement); N]) -> [FieldElement; M] + Send + Sync + Copy,
) -> [FieldElement; M] {
    let size = mles[0].0.len();
    if size * N * 2 > workload_size::<FieldElement>() {
        // Split slices
        let pairs = mles.map(|(p0, p1)| (p0.split_at(size / 2), p1.split_at(size / 2)));
        let left = pairs.map(|((l0, _), (l1, _))| (l0, l1));
        let right = pairs.map(|((_, r0), (_, r1))| (r0, r1));

        // Parallel recurse
        let (l, r) = rayon::join(
            || sumcheck_map_reduce_inner(left, map),
            || sumcheck_map_reduce_inner(right, map),
        );

        // Combine results
        array::from_fn(|i| l[i] + r[i])
    } else {
        let mut result = [FieldElement::zero(); M];
        for i in 0..size {
            let e = mles.map(|(p0, p1)| (p0[i], p1[i]));
            let local = map(e);
            result.iter_mut().zip(local).for_each(|(r, l)| *r += l);
        }
        result
    }
}

fn sumcheck_fold_map_reduce_inner<const N: usize, const M: usize>(
    mut mles: [[&mut [FieldElement]; 4]; N],
    fold: FieldElement,
    map: impl Fn([(FieldElement, FieldElement); N]) -> [FieldElement; M] + Send + Sync + Copy,
) -> [FieldElement; M] {
    let size = mles[0][0].len();
    if size * N * 4 > workload_size::<FieldElement>() {
        // Split slices
        let pairs = mles.map(|mles| mles.map(|p| p.split_at_mut(size / 2)));
        let (left, right) = unzip_double_array(pairs);

        // Parallel recurse
        let (l, r) = rayon::join(
            || sumcheck_fold_map_reduce_inner(left, fold, map),
            || sumcheck_fold_map_reduce_inner(right, fold, map),
        );

        // Combine results
        array::from_fn(|i| l[i] + r[i])
    } else {
        let mut result = [FieldElement::zero(); M];
        for i in 0..size {
            let e = array::from_fn(|j| {
                let mle = &mut mles[j];
                mle[0][i] += fold * (mle[2][i] - mle[0][i]);
                mle[1][i] += fold * (mle[3][i] - mle[1][i]);
                (mle[0][i], mle[1][i])
            });
            let local = map(e);
            result.iter_mut().zip(local).for_each(|(r, l)| *r += l);
        }
        result
    }
}

/// Trait which is used to add sumcheck functionality fo IOPattern
pub trait SumcheckIOPattern {
    /// Prover sends coefficients of the qubic sumcheck polynomial and the
    /// verifier sends randomness for the next sumcheck round
    fn add_sumcheck_polynomials(self, num_vars: usize, degree: usize) -> Self;
}

impl<IOPattern> SumcheckIOPattern for IOPattern
where
    IOPattern: FieldDomainSeparator<FieldElement>,
{
    fn add_sumcheck_polynomials(mut self, num_vars: usize, degree: usize) -> Self {
        for _ in 0..num_vars {
            self = self.add_scalars(degree + 1, "Sumcheck Polynomials");
            self = self.challenge_scalars(1, "Sumcheck Random");
        }
        self
    }
}

/// List of evaluations for eq(r, x) over the boolean hypercube
#[instrument(skip_all)]
pub fn calculate_evaluations_over_boolean_hypercube_for_eq(
    r: &[FieldElement],
) -> Vec<FieldElement> {
    let mut result = vec![FieldElement::zero(); 1 << r.len()];
    eval_eq(r, &mut result, FieldElement::one());
    result
}

/// Evaluates the equality polynomial recursively.
fn eval_eq(eval: &[FieldElement], out: &mut [FieldElement], scalar: FieldElement) {
    debug_assert_eq!(out.len(), 1 << eval.len());
    let size = out.len();
    if let Some((&x, tail)) = eval.split_first() {
        let (o0, o1) = out.split_at_mut(out.len() / 2);
        let s1 = scalar * x;
        let s0 = scalar - s1;
        if size > workload_size::<FieldElement>() {
            rayon::join(|| eval_eq(tail, o0, s0), || eval_eq(tail, o1, s1));
        } else {
            eval_eq(tail, o0, s0);
            eval_eq(tail, o1, s1);
        }
    } else {
        out[0] += scalar;
    }
}

/// Evaluates a qubic polynomial on a value
pub fn eval_qubic_poly(poly: &[FieldElement], point: &FieldElement) -> FieldElement {
    poly[0] + *point * (poly[1] + *point * (poly[2] + *point * poly[3]))
}

pub const fn uint_to_field(i: U256) -> FieldElement {
    FieldElement::new(BigInt(i.into_limbs()))
}

pub const HALF: FieldElement = uint_to_field(uint!(
    10944121435919637611123202872628637544274182200208017171849102093287904247809_U256
));

#[instrument()]
fn random_poly(size: usize) -> Vec<FieldElement> {
    let mut r = Vec::with_capacity(size);
    for i in 0..size {
        r.push(UniformRand::rand(&mut thread_rng()));
    }
    r
}

#[instrument(skip_all)]
fn prove_sumcheck_cubic(
    ps: [Vec<FieldElement>; 3],
    num_vars: usize,
    mut claimed_sum: FieldElement,

    merlin: &mut spongefish::ProverState,
) {
    let [mut a, mut b, mut c] = ps;
    let mut fold = None;

    for i in 0..num_vars {
        let alen = a.len();
        let [h0, hm1, hinf] =
            sumcheck_fold_map_reduce([&mut a, &mut b, &mut c], fold, |[a, b, c]| {
                [
                    a.0 * b.0 * c.0,
                    (a.0 + a.0 + a.1) * (b.0 + b.0 + b.1) * (c.0 + c.0 + c.1),
                    (a.1 - a.0) * (b.1 - b.0) * (c.1 - c.0),
                ]
            });
        if fold.is_some() {
            a.truncate(a.len() / 2);
            b.truncate(b.len() / 2);
            c.truncate(c.len() / 2);
        }

        let mut h_coeffs = [FieldElement::zero(); 4];
        h_coeffs[0] = h0;
        h_coeffs[3] = hinf;
        h_coeffs[2] = HALF * (claimed_sum + hm1 - h0 - h0 - h0);
        h_coeffs[1] = claimed_sum - h_coeffs[0] - h_coeffs[0] - h_coeffs[2] - h_coeffs[3];

        let _ = merlin.add_scalars(&h_coeffs);
        let mut next_ch = [FieldElement::zero()];
        let _ = merlin.fill_challenge_scalars(&mut next_ch);
        let next_ch = next_ch[0];
        fold = Some(next_ch);
        claimed_sum = eval_qubic_poly(&h_coeffs, &next_ch);
    }
}

#[instrument()]
fn run(logsize: usize) {
    let size = 1 << logsize;
    let mut p1 = random_poly(size);
    let mut p2 = random_poly(size);
    let mut p3 = random_poly(size);

    let mut claimed_sum = FieldElement::zero();
    for i in 0..size {
        claimed_sum += p1[i] * p2[i] * p3[i];
    }

    let pat = DomainSeparator::new("∑✅").add_sumcheck_polynomials(logsize, 3);
    let mut merlin = pat.to_prover_state();

    prove_sumcheck_cubic([p1, p2, p3], logsize, claimed_sum, &mut merlin);
}

fn main() {
    tracing_forest::init();
    run(19);
}
