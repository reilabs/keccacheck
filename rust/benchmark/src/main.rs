use ark_bn254::Fr;
use ark_ff::PrimeField;
use gkr::{prover::prove, reference::STATE, verifier::verify};
use std::env;

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

    let r = generate_r(&data, num_vars);
    // TODO Put a proper commitment here instead putting in constant
    let (proof, input, output) = prove(&data, r.clone());
    verify(num_vars, &output, &input, &proof, r);

    let mut reference_input: [u64; 25] = [0; 25];
    let mut reference_output: [u64; 25] = [0; 25];
    for i in 0..instances {
        for j in 0..STATE {
            reference_input[j] = input[j * instances + i];
            reference_output[j] = output[j * instances + i];
        }
        let mut buf = reference_input;
        keccak::f1600(&mut buf);
        assert_eq!(buf, reference_output);
    }

    println!("OK.");
}

// Deterministic way of generating log_N + 6 challenges
// that are fixed to the outputs, but without absorbing all
// the outputs to the sponge
pub fn generate_r(data: &[u64], num_vars: usize) -> Vec<Fr> {
    let mut challenges = Vec::<Fr>::with_capacity(num_vars);

    let mut hasher = blake3::Hasher::new();
    for value in data {
        hasher.update(&value.to_le_bytes());
    }
    let mut commitment = hasher.finalize();

    for _ in 0..num_vars {
        challenges.push(Fr::from_be_bytes_mod_order(commitment.as_bytes()));
        hasher.update(commitment.as_bytes());
        commitment = hasher.finalize();
    }
    challenges
}
