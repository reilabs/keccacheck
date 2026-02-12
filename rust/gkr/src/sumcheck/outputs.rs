use ark_bn254::Fr;
use ark_ff::Zero;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tracing::instrument;

use crate::sumcheck::util::{calculate_evaluations_over_boolean_hypercube_for_eq, update};
use crate::transcript::Prover;

/// Proof that the output words are consistent with an evaluation claim.
///
/// Given the 25 output lanes as field elements (words, not bits), proves:
/// $$\sum_{x \in \{0,1\}^{\log N}} \widetilde{eq}(\alpha, x) \cdot \sum_i \beta_i \cdot \widetilde{word}_i(x) = \text{sum}$$
///
/// After the sumcheck over instance indices, the verifier obtains:
/// - `r_x`: the random evaluation point produced during the sumcheck
/// - `word_rlc_eval`: the value $\sum_i \beta_i \cdot \widetilde{word}_i(r_x)$ at that point
///
/// The verifier checks the reduced claim using `eq(alpha, r_x)` (computable locally)
/// and `word_rlc_eval` (provided by the prover). A subsequent proof must then show that
/// `word_rlc_eval` is consistent with the underlying output bits.
pub struct EqProof {
    pub sum: Fr,
    pub r_x: Vec<Fr>,
    pub word_rlc_eval: Fr,
}

pub struct BitProof {
    pub sum: Fr,
    pub r_y: Vec<Fr>,     // This will always be of length 6
    pub bit_rlc_eval: Fr, // The final evaluation claim on the bit vector value $\sum_i \beta_i \cdot \tilde{b}_i(r_x, r_y)$ at that point
    pub pow_r_y: Fr,      // the evaluation of the power polynomial at r_y
}

pub fn prove_outputs(
    transcript: &mut Prover,
    num_vars: usize,
    alpha: &[Fr],
    words: &[Fr],
    beta: &[Fr],
    sum: Fr,
) -> EqProof {
    let instances = 1 << num_vars;
    assert_eq!(beta.len(), 25);
    assert_eq!(words.len(), 25 * instances);

    let mut eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(alpha);
    // Take chunks of each word, scale by corresponding Beta
    // Then sum up all the lens for an rlc over all lanes
    // Resulting polynomial will be log(instances)-variate
    let mut words = (0..25)
        .into_par_iter()
        .map(|el| {
            let slice = &words[(el * instances)..(el * instances + instances)];
            slice.iter().map(|&w| beta[el] * w).collect::<Vec<Fr>>()
        })
        .reduce_with(|mut a, b| {
            a.iter_mut().zip(b).for_each(|(a, b)| *a += b);
            a
        })
        .unwrap(); // reduce_with returns None only for empty iterators; 0..25 is non-empty

    prove_sumcheck_words(transcript, num_vars, &mut eq_alpha, &mut words, sum)
}

// Sumcheck for
// $ \sum_{ x \in \{0, 1\}^{\text{log N}} }\widetilde{eq} (\alpha, x)\cdot  \sum_i \beta_i \cdot \widetilde{word}_i(x)$
#[instrument(skip_all)]
pub fn prove_sumcheck_words(
    transcript: &mut Prover,
    size: usize,
    mut e: &mut [Fr],
    mut words: &mut [Fr],
    mut sum: Fr,
) -> EqProof {
    // Assert that the polynomials are of the correct size
    // i.e log(N) variables where N is the number of instances
    assert_eq!(e.len(), 1 << size);
    assert_eq!(words.len(), 1 << size);

    let mut rs: Vec<Fr> = Vec::with_capacity(size);
    for _ in 0..size {
        // p(t) = p0 + p1 ⋅ t + p2 ⋅ t^2
        let mut p0 = Fr::zero();
        let mut p2 = Fr::zero();
        let (e0, e1) = e.split_at(e.len() / 2);
        let (w0, w1) = words.split_at(words.len() / 2);

        for j in 0..e0.len() {
            // Evaluation at 0
            p0 += e0[j] * w0[j];

            // Evaluation at ∞ (leading coefficient)
            p2 += (e1[j] - e0[j]) * (w1[j] - w0[j]);
        }

        // Derive p1 from p(0) + p(1) = sum
        let p1 = sum - p0 - p0 - p2;
        assert_eq!(sum, p0 + p0 + p1 + p2);

        transcript.write(p1);
        transcript.write(p2);

        let r = transcript.read();
        rs.push(r);

        // Fold polynomials at r
        e = update(e, r);
        words = update(words, r);

        // Update sum = p(r)
        sum = p0 + r * (p1 + r * p2);
    }

    assert_eq!(e[0] * words[0], sum);
    transcript.write(words[0]);

    EqProof {
        sum,
        r_x: rs,
        word_rlc_eval: words[0],
    }
}

/// Proof that the word RLC evaluation is consistent with the underlying output bits.
///
/// Given the 25×64 output bits (one 64-bit lane per word), first partially evaluates
/// the multilinear extension of the bits at the point `r_x` produced by the word-level
/// sumcheck, reducing the instance dimension. Then proves:
/// $$\sum_{y \in \{0,1\}^6} \left(\sum_i \beta_i \cdot \widetilde{b}_i(r_x, y)\right) \cdot \text{pow}(y) = \text{sum}$$
///
/// where $\text{pow}(y) = \sum_{j=0}^{5} 2^j \cdot y_j$ reconstructs the word value from bits.
///
/// After the sumcheck over the 6 bit-index variables, the verifier obtains:
/// - `r_y`: the random evaluation point produced during the sumcheck
/// - `bit_rlc_eval`: the value $\sum_i \beta_i \cdot \widetilde{b}_i(r_x, r_y)$
///
/// A subsequent proof must then show that `bit_rlc_eval` is consistent with the
/// actual bit values.
pub fn prove_bits(
    transcript: &mut Prover,
    r_x: &[Fr],
    bits: &mut [Fr],
    beta: &[Fr],
    sum: Fr,
) -> BitProof {
    let per_lane = bits.len() / 25;

    // RLC over the 25 lanes first, before folding at r_x.
    let mut bits_rlc = (0..25)
        .into_par_iter()
        .map(|el| {
            let slice = &bits[(el * per_lane)..(el * per_lane + per_lane)];
            slice.iter().map(|&w| beta[el] * w).collect::<Vec<Fr>>()
        })
        .reduce_with(|mut a, b| {
            a.iter_mut().zip(b).for_each(|(a, b)| *a += b);
            a
        })
        .unwrap(); // reduce_with returns None only for empty iterators; 0..25 is non-empty

    // Now fold the instance dimension at r_x
    let mut folded = &mut bits_rlc[..];
    for r in r_x.iter() {
        folded = update(folded, *r);
    }
    let mut bits = folded.to_vec();

    // Create the power polynomial
    let n = 6;
    let mut powers: Vec<Fr> = (0..1 << n).map(|i| Fr::from(1u64 << i)).collect();

    println!("{powers:?}");
    #[cfg(debug_assertions)]
    {
        assert_eq!(bits.len(), (1 << 6));
        let mut c_sum = Fr::zero();
        for x in 0..(1 << 6) {
            c_sum += bits[x] * powers[x];
        }
        assert_eq!(c_sum, sum);
    }

    prove_sumcheck_bits(transcript, &mut bits, &mut powers, sum)
}

fn prove_sumcheck_bits(
    transcript: &mut Prover,
    mut bits: &mut [Fr],
    mut powers: &mut [Fr],
    mut sum: Fr,
) -> BitProof {
    let mut rs: Vec<Fr> = Vec::with_capacity(6);
    println!("{:?}, {:?}", bits.len(), powers.len());
    for _ in 0..6 {
        // p(t) = p0 + p1 ⋅ t + p2 ⋅ t^2
        let mut p0 = Fr::zero();
        let mut p2 = Fr::zero();
        let (b0, b1) = bits.split_at(bits.len() / 2);
        let (w0, w1) = powers.split_at(powers.len() / 2);

        for j in 0..b0.len() {
            // Evaluation at 0
            p0 += b0[j] * w0[j];

            // Evaluation at ∞ (leading coefficient)
            p2 += (b1[j] - b0[j]) * (w1[j] - w0[j]);
        }

        // Derive p1 from p(0) + p(1) = sum
        let p1 = sum - p0 - p0 - p2;
        assert_eq!(sum, p0 + p0 + p1 + p2);

        transcript.write(p1);
        transcript.write(p2);

        let r = transcript.read();
        rs.push(r);

        // Fold polynomials at r
        bits = update(bits, r);
        powers = update(powers, r);

        // Update sum = p(r)
        sum = p0 + r * (p1 + r * p2);
    }

    assert_eq!(bits[0] * powers[0], sum);
    transcript.write(bits[0]);

    BitProof {
        sum,
        r_y: rs,
        bit_rlc_eval: bits[0],
        pow_r_y: powers[0],
    }
}
