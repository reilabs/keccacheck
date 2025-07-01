use ark_bn254::Fr;
use ark_ff::PrimeField;
use std::ffi::c_void;
use crate::reference::KeccakRoundState;

mod reference;

#[repr(C)]
pub struct KeccakInstance {
    data: Vec<Fr>,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_init(ptr: *const u8, len: usize) -> *mut c_void {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    unsafe {
        let input: &[u8] = std::slice::from_raw_parts(ptr, len);
        println!("input: {input:?}");


        let buf: Vec<u64> = (0..len/8)
            .map(|i| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&input[i*8..(i+1)*8]);
                u64::from_be_bytes(bytes)
            })
            .collect();
        let (inp, out) = buf.split_at(buf.len() / 2);

        let mut data = [0u64; 25];
        data.iter_mut().zip(inp.iter()).for_each(|(s, b)| *s = *b);

        let state = KeccakRoundState::at_round(&data, 0);
        println!("state: {state:?}");

        // let buf: &[u64] = std::slice::from_raw_parts(ptr as *const u64, len / 8);
        // println!("buf: {buf:?}");


        let fr_ary = (0..len / 4)
            .map(|i| Fr::from_be_bytes_mod_order(&input[i * 4..(i + 1) * 4]))
            .collect::<Vec<_>>();
        println!("fr_ary: {fr_ary:?}");

        let instance = KeccakInstance { data: fr_ary };

        Box::into_raw(Box::new(instance)) as *mut c_void
    }
}

/// Frees memory allocated by `keccak_init`.
///
/// # Safety
/// The pointer must be a valid pointer to a `KeccakInstance` that was created by `keccak_init`.
/// It must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        // Take ownership of the pointer and drop the Box, deallocating the memory.
        unsafe {
            let _ = Box::from_raw(ptr as *mut KeccakInstance);
        }
    }
}
