use ark_bn254::Fr;
use ark_ff::{AdditiveGroup};
use itertools::izip;

use crate::{reference::{keccak_round, ROUND_CONSTANTS}, sumcheck::{iota::prove_sumcheck_iota, util::{calculate_evaluations_over_boolean_hypercube_for_eq, eval_mle, to_poly, verify_sumcheck, xor}}, transcript::{Prover, Verifier}};

mod poseidon;
mod reference;
mod sumcheck;
mod transcript;

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
