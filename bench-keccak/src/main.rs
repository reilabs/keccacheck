use crate::prover::prove;
use crate::reference::{ROUND_CONSTANTS, STATE, keccak_round};
use crate::verifier::verify;
use std::env;

mod poseidon;
mod reference;
mod sumcheck;
mod transcript;

mod prover;
mod verifier;

fn main() {
    tracing_forest::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <number>", args[0]);
        std::process::exit(1);
    }
    let num_vars: usize = args[1].parse().unwrap();

    let instances = 1usize << (num_vars - 6);

    let data = (0..(instances * STATE))
        .map(|i| i as u64)
        .collect::<Vec<_>>();
    let (proof, input, output) = prove(&data);
    verify(num_vars, &output, &input, &proof);
    println!("OK.")
}
