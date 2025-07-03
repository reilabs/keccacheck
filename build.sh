cd rust
cargo build
cd ../gnark
cp ../rust/target/debug/libkeccak.a .
go clean --cache
go build