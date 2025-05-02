use std::env;

use keccak_parallel::run_keccak_f;

#[cfg(test)]
mod basic_parallel;
#[cfg(test)]
mod basic_sparse;
#[cfg(test)]
mod cmp;
#[cfg(test)]
mod keccak;
pub mod keccak_definition;
mod keccak_parallel;
#[cfg(test)]
mod keccak_sparse;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <number>", args[0]);
        std::process::exit(1);
    }
    let instances = args[1].parse().unwrap();
    run_keccak_f(instances);
}
