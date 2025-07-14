use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_path = format!("{crate_dir}/bindings.h");
    cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_language(cbindgen::Language::C)
        .with_include_version(false)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(&out_path);
}
