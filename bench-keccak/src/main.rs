use crate::prover::prove;
use crate::reference::{ROUND_CONSTANTS, keccak_round};
use crate::verifier::verify;

mod poseidon;
mod reference;
mod sumcheck;
mod transcript;

mod prover;
#[cfg(test)]
mod test;
mod verifier;

fn main() {
    let input = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    ];
    let mut buf = input;
    let layers = keccak_round(&mut buf, ROUND_CONSTANTS[0]);

    let num_vars = 6; // a single u64, one instance
    let proof = prove(num_vars, &layers);
    verify(num_vars, &layers[0], &layers[3], &proof);
    println!("OK.")
}
