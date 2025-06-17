# Keccacheck

Keccacheck - a play on words keccak and sumcheck - is a GKR-style prover for Keccak hash functions. Our prover uses lots of rounds of sumcheck internally, hence the name.

The high level idea is to represent a single Keccak-F as layered polynomials. Multiple instances of Keccak-F can be proven together, increasing the number of variables on each layer by only $log_2(instances)$ - making the verifier very efficient for lots of Keccaks at once.

Since these proofs are rather large, the idea is to wrap proof verification into another proof system that produces more succint proofs (using gnark).

## Benchmarking

Run `RUSTFLAGS='-C target-cpu=native' cargo run --profile=optimized -- {num_variables}`.

`num_variables` must be greater than 6 (a single keccak instance). This will prove $2^{num_variables - 6}$ instances of keccak.
