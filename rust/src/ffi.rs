use crate::reference::KeccakRoundState;
use std::ffi::c_void;

mod reference;

#[repr(C)]
/// Represents the internal Keccak state
pub struct KeccakInstance {
    pub data: Vec<u64>,
}

#[unsafe(no_mangle)]
/// Returns a C style generic pointer to a KeccakInstance
/// We use this to maintain a referencable Keccak internal state
/// for all 24 rounds
/// The data passed in the argument should be the input and output bits of
/// a KeccakF function
/// We construct a buffer that holds the state of all 24 rounds sequentially.
/// Each round consists of 200 bytes, the total buffer we should return is 4.8 kB
pub unsafe extern "C" fn keccacheck_init(ptr: *const u8, len: usize) -> *mut c_void {
    // SAFETY: Caller must ensure ptr is valid for len bytes
    unsafe {
        // Gets the words from the data at the pointer
        let data: &[u8] = std::slice::from_raw_parts(ptr, len);
        
        let words: Vec<u64> = (0..len / 8)
            .map(|i| {
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&data[i * 8..(i + 1) * 8]);
                u64::from_le_bytes(bytes)
            })
            .collect();

        // Seperate input/output of the KeccakF function
        let (inp, out) = words.split_at(words.len() / 2);
        let mut input = [0u64; 25];
        
        input.iter_mut().zip(inp.iter()).for_each(|(s, b)| *s = *b);
        
        let mut output = [0u64; 25];
        output.iter_mut().zip(out.iter()).for_each(|(s, b)| *s = *b);
       
        // Sanity check on the input and output
        let mut permuted_input: [u64; 25] = input;
        keccak::f1600(&mut permuted_input);
        assert_eq!(permuted_input, output);

        let mut state = KeccakRoundState::at_round(&input, 0);
        let mut state_data: Vec<u64> = Vec::with_capacity(600);
        
        for _ in 0..23{
            state_data.extend_from_slice(state.iota.as_slice());
            state = state.next();
           
        }
        state_data.extend_from_slice(state.iota.as_slice());
        
        let instance = KeccakInstance { data: state_data };

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

#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use crate::{keccacheck_init, KeccakInstance};

    #[test]
    fn test_keccacheck_init() {
        // Run Keccacheck init and check that the
        // last round in the buffer is consistent with the expected output
        let  output = [
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

            let mut data = [0u64;50];
            data[25..].copy_from_slice(&output);
            let ptr : *const [u64] = &data;

            let result: *mut c_void = unsafe {
            keccacheck_init(ptr as *const u8, 400)
            };
            let instance =unsafe{ &*(result as *const KeccakInstance)};
            
            assert_eq!(output[0], instance.data[575]);
            assert_eq!(output[24], instance.data[599])
         }
}
