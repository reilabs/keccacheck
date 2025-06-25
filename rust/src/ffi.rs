#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_init() -> i64 {
    println!("called rust hint");
    5
}
