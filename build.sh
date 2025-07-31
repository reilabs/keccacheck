cd rust
RUSTFLAGS='-C target-cpu=native' cargo build --profile=optimized
cd ../gnark
make