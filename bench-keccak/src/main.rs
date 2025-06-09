use std::str::FromStr;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, One, Zero};
use itertools::izip;

use crate::sumcheck::chi::{prove_chi, prove_sumcheck_chi};
use crate::sumcheck::util::add_col;
use crate::{
    reference::{ROUND_CONSTANTS, keccak_round},
    sumcheck::{
        iota::prove_sumcheck_iota,
        util::{
            calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly,
            verify_sumcheck, xor,
        },
    },
    transcript::{Prover, Verifier},
};
use crate::sumcheck::iota::prove_iota;

mod poseidon;
mod reference;
mod sumcheck;
mod transcript;

#[cfg(test)]
mod test;

fn main() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input.clone();
    let output = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

    println!("inp {input:?}");
    println!("out {output:?}");

    let num_vars = 6; // a single u64, one instance

    let mut prover = Prover::new();
    let alpha = (0..num_vars).map(|_| prover.read()).collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| prover.read()).collect::<Vec<_>>();

    // write final output sum
    let sum: Fr = output[0]
        .iter()
        .enumerate()
        .map(|(i, x)| {
            let poly = to_poly(*x);
            beta[i] * eval_mle(&poly, &alpha)
        })
        .sum();

    prover.write(sum);

    // prove iota
    let iota_proof = prove_iota(&mut prover, num_vars, &alpha, &beta, &output[1], sum);

    // combine subclaims chi_00 and chi_rlc
    let x = prover.read();
    let y = prover.read();
    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);
    let sum = beta[0] * iota_proof.chi_00 + y * iota_proof.chi_rlc;

    // prove chi
    let chi_proof = prove_chi(&mut prover, num_vars, &iota_proof.r, &beta, &output[2], sum);

    let proof = prover.finish();

    // Verify
    let mut verifier = Verifier::new(&proof);

    let alpha = (0..num_vars)
        .map(|_| verifier.generate())
        .collect::<Vec<_>>();
    let mut beta = (0..25).map(|_| verifier.generate()).collect::<Vec<_>>();

    let expected_sum = (0..25)
        .map(|i| beta[i] * eval_mle(&to_poly(output[0][i]), &alpha))
        .sum();


    // TODO: feed output to the prover/verifier before obtaining alpha

    let vs = verifier.read();
    assert_eq!(vs, expected_sum);
    let (ve, vrs) = verify_sumcheck::<3>(&mut verifier, num_vars, vs);
    assert_eq!(vrs, iota_proof.r);
    assert_eq!(ve, iota_proof.sum);

    let chi_00 = verifier.read();
    let chi_rlc = verifier.read();
    //assert_eq!(e_eq * (beta[0] * xor(chi_00, e_rc) + chi_rlc), pe);

    let x = verifier.generate();
    let y = verifier.generate();

    beta[0] *= x;
    beta.iter_mut().skip(1).for_each(|b| *b *= y);

    // TODO: verifier needs to combine sublaims and continue recursively before we get to the last step
    let expected_sum = beta[0] * chi_00 + y * chi_rlc;

    let (ve, vrs) = verify_sumcheck::<4>(&mut verifier, num_vars, expected_sum);
    assert_eq!(vrs, chi_proof.r);
    assert_eq!(ve, chi_proof.sum);

    // Verify last step
    //
    // NOTE: being lazy here, we've already tested prs and pe values after proving step.
    // Here just making sure they are the same. In practice, this should be a separate implementation.
}
