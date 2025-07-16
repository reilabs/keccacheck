use ark_bn254::Fr;
use std::ffi::c_void;

use ark_ff::{BigInteger, PrimeField};
use gkr::{prover::prove, reference::KeccakRoundState};
#[repr(C)]
/// Represents the internal Keccak state
pub struct KeccakInstance {
    pub data: Vec<u64>,
}

#[unsafe(no_mangle)]
/// Returns a C style generic pointer to a KeccakInstance
/// We use this to maintain a referencable Keccak internal state
/// for all 24 rounds
/// The data passed in the argument should be the input bits of
/// a KeccakF function
/// We construct a buffer that holds the state of all 24 rounds sequentially.
/// Each round consists of 200 bytes, the total buffer we should return is 4.8 kB * number of instances
/// # Safety
/// The pointer must be a valid pointer to input words to the KeccakF function
/// It must not have been freed already.
pub unsafe extern "C" fn keccacheck_init(ptr: *const u8, len: usize) -> *mut c_void {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    unsafe {
        // We need a multiple of 200 bytes as input consists of 25 words of
        // 8 bytes each
        assert_eq!(len % 200, 0);
        let n = len / 200;

        // Gets the words from the data at the pointer
        let data: &[u8] = std::slice::from_raw_parts(ptr, len);
        let words: Vec<u64> = (0..len / 8)
            .map(|i| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[i * 8..(i + 1) * 8]);
                u64::from_be_bytes(bytes)
            })
            .collect();

        let mut input = vec![0u64; 25 * n];
        input
            .iter_mut()
            .zip(words.iter())
            .for_each(|(s, b)| *s = *b);

        // For each instance we have 25 * 24 = 600 words
        let mut state_data: Vec<u64> = Vec::with_capacity(600 * n);

        for i in 0..n {
            let input_i = &mut input[25 * i..25 * i + 25];
            let mut state = KeccakRoundState::at_round(input_i, 0);
            for _ in 0..23 {
                state_data.extend_from_slice(state.iota.as_slice());
                state = state.next();
            }
            state_data.extend_from_slice(state.iota.as_slice());
        }

        let mut instance = KeccakInstance { data: state_data };

        let ptr = instance.data.as_mut_ptr() as *mut c_void;
        std::mem::forget(instance.data);
        ptr
    }
}

/// Frees memory allocated by `keccak_init`.
///
/// # Safety
/// The pointer must be a valid pointer to a `KeccakInstance` that was created by `keccak_init`.
/// It must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_free(ptr: *mut c_void, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr as *mut u64, len, len);
            // Dropped here: memory freed safely
        }
    }
}

#[repr(C)]
pub struct KeccacheckResult {
    pub proof_ptr: *mut c_void,
    pub input_ptr: *mut c_void,
    pub output_ptr: *mut c_void,
}

/// Constructs a GKR proof of a KeccakF permutation
///
/// Takes a pointer to a u8 slice representing the input to a KeccakF function
/// and returns the proof in the form of three pointers:
/// 1) Pointer to the field elements represetning the proof
/// 2) Pointer to the input to the function
/// 3) Pointer to the output of the function
///
/// # Safety
///
/// This function is marked `unsafe` because it dereferences a raw pointer and constructs
/// a slice from it using `std::slice::from_raw_parts`. The caller **must** ensure the following:
///
/// - `ptr` must be non-null and properly aligned for `u8`.
/// - `ptr` must point to a valid memory region that contains at least `instances * 8 * 25` contiguous `u8` elements.
/// - The memory region starting at `ptr` and extending for `len * 8 * 25* size_of::<u8>()` bytes must be valid
///   for reads for the lifetime of the call.
/// - The memory must not be mutated by other threads while this function is executing.
///
/// Violating any of these requirements results in **undefined behavior**.
///
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_prove(
    ptr: *const u8,
    instances: usize,
    r_ptr: *const u8,
) -> *mut c_void {
    unsafe {
        let log_n = instances.ilog2() as usize;
        // Safety: Caller must ensure ptr is valid and instances is correct.
        let data: &[u8] = std::slice::from_raw_parts(ptr, instances * 25 * 8);
        let data: Vec<u64> = (0..instances * 25)
            .map(|i| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[i * 8..(i + 1) * 8]);
                u64::from_be_bytes(bytes)
            })
            .collect();

        let r_bytes: &[u8] = std::slice::from_raw_parts(r_ptr, 32 * (6 + log_n));
        let mut r = Vec::with_capacity(6 + log_n);
        for i in 0..(6 + log_n) {
            let chunk = &r_bytes[i * 32..(i + 1) * 32];
            r.push(Fr::from_be_bytes_mod_order(chunk));
        }
        let (proof, mut input, mut output) = prove(&data, r);
        let mut proof: Vec<u8> = proof
            .iter()
            .flat_map(|el| el.into_bigint().to_bytes_le())
            .collect();

        let proof_ptr = proof.as_mut_ptr() as *mut c_void;
        let input_ptr = input.as_mut_ptr() as *mut c_void;
        let output_ptr = output.as_mut_ptr() as *mut c_void;

        // Prevent Rust from freeing the memory so it can be used by caller
        std::mem::forget(proof);
        std::mem::forget(input);
        std::mem::forget(output);

        let result = Box::new(KeccacheckResult {
            proof_ptr,
            input_ptr,
            output_ptr,
        });
        // TODO Consider limiting the output of this function to just the Proof
        Box::into_raw(result) as *mut c_void
    }
}

/// # Safety
///
/// This function is unsafe because it operates on raw pointers received via FFI,
/// requiring the caller to uphold several invariants for memory safety:
///
/// - `proof_ptr`, `input_ptr`, and `output_ptr` must each be a valid
///   pointer to memory previously allocated by `keccacheck_proof` (or the corresponding
///   allocation function) with the same ABI and layout expectations.
/// - The function will deallocate the memory these pointers reference, so after calling
///   this function, the pointers must not be used again as they are considered dangling.
/// - `instances` must match the number of instances originally allocated to ensure
///   correct deallocation logic. Providing an incorrect `instances` value may result
///   in undefined behavior, including memory corruption or double free.
/// - The caller must ensure that no other references (raw or safe) are used to access
///   or modify the memory pointed to by these pointers during or after the call.
/// - This function is not thread-safe and must not be called concurrently with any
///   operation that accesses or modifies the memory these pointers reference.
///
/// Violating any of these requirements will result in undefined behavior.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keccacheck_proof_free(
    proof_ptr: *mut c_void,
    input_ptr: *mut c_void,
    output_ptr: *mut c_void,
    instances: usize,
) {
    unsafe {
        if !input_ptr.is_null() {
            let len = 25 * instances;
            // SAFETY: Caller must guarantee that input_ptr was allocated as a Vec<u64> of length len
            let _ = Vec::from_raw_parts(input_ptr as *mut u64, len, len);
        }
        if !output_ptr.is_null() {
            let len = 25 * instances;
            let _ = Vec::from_raw_parts(output_ptr as *mut u64, len, len);
        }
        //See proof size table in README
        let vars: usize = 6 + instances.ilog2() as usize;
        let f_elts: usize = 552 * vars + 2929;
        let _ = Vec::<Fr>::from_raw_parts(proof_ptr as *mut Fr, f_elts, f_elts);
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::c_void, slice};

    use crate::keccacheck_init;

    #[test]
    fn test_keccacheck_init() {
        // Run Keccacheck init and check that the
        // last round in the buffer is consistent with the expected output
        let output = [
            0xF1258F7940E1DDE7,
            0x84D5CCF933C0478A,
            0xD598261EA65AA9EE,
            0xBD1547306F80494D,
            0x8B284E056253D057,
            0xFF97A42D7F8E6FD4,
            0x90FEE5A0A44647C4,
            0x8C5BDA0CD6192E76,
            0xAD30A6F71B19059C,
            0x30935AB7D08FFC64,
            0xEB5AA93F2317D635,
            0xA9A6E6260D712103,
            0x81A57C16DBCF555F,
            0x43B831CD0347C826,
            0x01F22F1A11A5569F,
            0x05E5635A21D9AE61,
            0x64BEFEF28CC970F2,
            0x613670957BC46611,
            0xB87C5A554FD00ECB,
            0x8C3EE88A1CCF32C8,
            0x940C7922AE3A2614,
            0x1841F924A2C509E4,
            0x16F53526E70465C2,
            0x75F644E97F30A13B,
            0xEAF1FF7B5CECA249,
        ];
        const N: usize = 16;
        let output = output.map(u64::swap_bytes);
        let mut data = [0u64; N * 50];

        for i in 0..N {
            data[N * 25 + i * 25..N * 25 + i * 25 + 25].copy_from_slice(&output);
        }

        let ptr: *const [u64] = &data;

        let result: *mut c_void = unsafe { keccacheck_init(ptr as *const u8, N * 400) };
        assert!(!result.is_null());
        let words: &[u64] = unsafe { slice::from_raw_parts(result as *const u64, 600 * N) };
        for i in 0..N {
            for j in 0..25 {
                let expected = output[j];
                let actual = words[600 * i + 575 + j];
                assert_eq!(
                    actual.swap_bytes(),
                    expected,
                    "Mismatch at instance {}, word {}, expected {:016x}, got {:016x}",
                    i,
                    575 + j,
                    expected,
                    actual
                );
            }
        }
    }
}
