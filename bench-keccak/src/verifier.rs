use crate::reference::ROUND_CONSTANTS;
use crate::sumcheck::util::{
    add_col, calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly,
    verify_sumcheck, xor,
};
use crate::transcript::Verifier;
use ark_bn254::Fr;
use ark_ff::{One, Zero};

pub fn verify(num_vars: usize, output: &[u64], input: &[u64], proof: &[Fr]) {
    let mut verifier = Verifier::new(&proof);

    // TODO: feed output to the verifier before obtaining alpha
    let alpha = (0..num_vars)
        .map(|_| verifier.generate())
        .collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    // TODO: we can maybe skip this step and only depend on the sum in the transcript
    // correct sum is required to recover sumcheck polynomials
    let expected_sum = (0..25)
        .map(|i| beta[i] * eval_mle(&to_poly(output[i]), &alpha))
        .sum();
    let sum = verifier.read();
    assert_eq!(sum, expected_sum);

    // verify iota
    let eq = calculate_evaluations_over_boolean_hypercube_for_eq(&alpha);
    let rc = to_poly(ROUND_CONSTANTS[0]);

    let (ve, vrs) = verify_sumcheck::<3>(&mut verifier, num_vars, sum);
    let chi_00 = verifier.read();
    let chi_rlc = verifier.read();

    let e_eq = eval_mle(&eq, &vrs);
    let e_rc = eval_mle(&rc, &vrs);
    assert_eq!(e_eq * (beta[0] * xor(chi_00, e_rc) + chi_rlc), ve);

    // combine subclaims chi_00 and chi_rlc
    let x = verifier.generate();
    let y = verifier.generate();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let expected_sum = beta[0] * chi_00 + y * chi_rlc;

    // verify chi, assume pi is the final layer
    let mut eq = calculate_evaluations_over_boolean_hypercube_for_eq(&vrs);
    let mut pis = input.iter().map(|u| to_poly(*u)).collect::<Vec<_>>();

    let (ve, vrs) = verify_sumcheck::<4>(&mut verifier, num_vars, expected_sum);

    let e_eq = eval_mle(&eq, &vrs); // TODO: can evaluate eq faster
    let pi = pis
        .iter()
        .map(|poly| eval_mle(&poly, &vrs))
        .collect::<Vec<_>>();
    let mut checksum_pi = Fr::zero();
    for i in 0..pi.len() {
        checksum_pi +=
            e_eq * beta[i] * xor(pi[i], (Fr::one() - pi[add_col(i, 1)]) * (pi[add_col(i, 2)]));
    }
    assert_eq!(checksum_pi, ve);
}
