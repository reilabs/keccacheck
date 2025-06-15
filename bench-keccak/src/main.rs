use crate::prover::prove;
use crate::reference::{ROUND_CONSTANTS, keccak_round, STATE};
use crate::verifier::verify;

mod poseidon;
mod reference;
mod sumcheck;
mod transcript;

mod prover;
mod verifier;

// High-level tasks:
// - TODO: support for multiple instances
//     - TODO: derive_rot_evaluations_from_eq needs to be updated
// - TODO: add benchmarks
// - TODO: perf: use multithreaded sumcheck
// - TODO: perf: reuse pi polynomials in sumcheck
// - TODO: perf: make sure nested loops leverage CPU cache
// - TODO: perf: remove unnecessary allocations

fn main() {
    let num_vars = 7; // two instances
    let instances = 1usize << (num_vars - 6);

    let mut data = (0..(instances * STATE)).map(|i| i as u64).collect::<Vec<_>>();
    let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

    let proof = prove(num_vars, &state);
    verify(num_vars, &state.iota, &state.a, &proof);
    println!("OK.")
}
