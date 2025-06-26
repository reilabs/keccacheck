use std::env;
use cbindgen;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=src/ffi.rs");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = format!("{}/../gnark/bindings.h", crate_dir);
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_include_version(false)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&out_path);

    // Determine build profile (debug or release)
    let profile = env::var("PROFILE").unwrap();
    let lib_path = format!("{}/target/{}/libkeccak.a", crate_dir, profile);
    let dest_path = format!("{}/../gnark/libkeccak.a", crate_dir);
    if Path::new(&lib_path).exists() {
        fs::copy(&lib_path, &dest_path).expect("Failed to copy libkeccak.a to gnark/");
    }
}
