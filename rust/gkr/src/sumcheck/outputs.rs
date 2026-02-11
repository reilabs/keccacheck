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
/// - `word_rlc`: the value $\sum_i \beta_i \cdot \widetilde{word}_i(r_x)$ at that point
///
/// The verifier checks the reduced claim using `eq(alpha, r_x)` (computable locally)
/// and `word_rlc` (provided by the prover). A subsequent proof must then show that
/// `word_rlc` is consistent with the underlying output bits.
pub struct EqProof {
    pub _sum: Fr,
    pub r_x: Vec<Fr>,
    pub word_rlc: Fr,
}

pub fn prove_outputs(
    transcript: &mut Prover,
    instances: usize,
    alpha: &[Fr],
    words: &[Fr],
    beta: &[Fr],
    sum: Fr,
) -> EqProof {
    assert_eq!(beta.len(), 25);
    assert_eq!(words.len(), 25 * instances);

    let mut eq_alpha = calculate_evaluations_over_boolean_hypercube_for_eq(alpha);
    // Take chunks of each line, scale by corresponding Beta
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

    prove_sumcheck_outputs(transcript, instances, &mut eq_alpha, &mut words, sum)
}

// Sumcheck for
// $ \sum_{ x \in \{0, 1\}^{\text{log N}} }\widetilde{eq} (\alpha, x)\cdot  \sum_i \beta_i \cdot \widetilde{word}_i(x)$
#[instrument(skip_all)]
pub fn prove_sumcheck_outputs(
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
        _sum: sum,
        r_x: rs,
        word_rlc: words[0],
    }
}
