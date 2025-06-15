use std::env;
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
// - TODO: add benchmarks
// - TODO: perf: use multithreaded sumcheck
// - TODO: perf: reuse pi polynomials in sumcheck
// - TODO: perf: make sure nested loops leverage CPU cache
// - TODO: perf: remove unnecessary allocations

fn main() {
    tracing_forest::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <number>", args[0]);
        std::process::exit(1);
    }
    let num_vars = args[1].parse().unwrap();
    
    let instances = 1usize << (num_vars - 6);

    let mut data = (0..(instances * STATE)).map(|i| i as u64).collect::<Vec<_>>();
    let state = keccak_round(&mut data, ROUND_CONSTANTS[0]);

    let proof = prove(num_vars, &state);
    verify(num_vars, &state.iota, &state.a, &proof);
    println!("OK.")
}
