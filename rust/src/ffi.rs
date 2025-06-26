use ark_bn254::Fr;
use ark_ff::{PrimeField, BigInteger};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_init(ptr: *const u8, len: usize, out_len: *mut usize) -> *mut u8 {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    let input: &[u8] = unsafe { std::slice::from_raw_parts(ptr, len) };

    let mut fr = Fr::from_be_bytes_mod_order(input);
    fr += fr;

    // Serialize fr to bytes using into_bigint().to_bytes_be()
    let mut buffer = fr.into_bigint().to_bytes_be();
    let out_ptr = buffer.as_mut_ptr();
    let out_len_val = buffer.len();
    unsafe { std::ptr::write(out_len, out_len_val) };
    std::mem::forget(buffer); // Prevent Rust from freeing the buffer
    out_ptr
}

/// Frees memory allocated by keccacheck_init.
///
/// # Safety
/// The pointer and length must be exactly as returned by keccacheck_init and must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = unsafe { Vec::from_raw_parts(ptr, len, len) };
        // Vec is dropped here, freeing the memory
    }
}
