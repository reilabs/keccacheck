use ark_bn254::Fr;
use ark_ff::PrimeField;
use std::ffi::c_void;
use crate::reference::KeccakRoundState;

mod reference;

#[repr(C)]
/// Represents the internal Keccak state
pub struct KeccakInstance {
    data: Vec<Fr>,
}

#[unsafe(no_mangle)]
/// Returns a C style generic pointer to a KeccakInstance
/// We use this to maintain a referencable Keccak internal state
/// for all 24 rounds
/// The data passed in the argument should be the input and output bits of 
/// a KeccakF function
/// We construct a buffer that holds the state of all 24 rounds sequentially
/// each round consists of 200 bytes, the total buffer we should return is 4.8 kB
pub unsafe extern "C" fn keccacheck_init(ptr: *const u8, len: usize) -> *mut c_void {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    unsafe {
        // Gets the words from the data at the pointer
        let input: &[u8] = std::slice::from_raw_parts(ptr, len);
        println!("input: {input:?}");
        let buf: Vec<u64> = (0..len/8)
            .map(|i| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&input[i*8..(i+1)*8]);
                u64::from_be_bytes(bytes)
            })
            .collect();

        // State consists of the word values of the first half of the input
        let (inp, _) = buf.split_at(buf.len() / 2);
        let mut data = [0u64; 25];
        data.iter_mut().zip(inp.iter()).for_each(|(s, b)| *s = *b);

        let state = KeccakRoundState::at_round(&data, 0);
        println!("state: {state:?}");

        // let buf: &[u64] = std::slice::from_raw_parts(ptr as *const u64, len / 8);
        // println!("buf: {buf:?}");

        //Instance consists of 32 bit array values converted into Field elementss
        //TODO Understand why this is helpful at all
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

//TODO We need to add a two more FFI functions
// 1) Keccacheck_prove which will return a proof for the stage specified in an enum

// 2) Keccacheck_proof_free which will free memory being used for a proof
