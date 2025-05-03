# Keccacheck

## Benchmarking

Run `RUSTFLAGS='-C target-cpu=native' cargo run --profile=optimized --features parallel -- {num_instances}`. `num_instances` must be a power of two.