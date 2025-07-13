#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define COLUMNS 5

#define ROWS 5

#define STATE (COLUMNS * ROWS)

/**
 * Returns a C style generic pointer to a KeccakInstance
 * We use this to maintain a referencable Keccak internal state
 * for all 24 rounds
 * The data passed in the argument should be the input and output bits of
 * a KeccakF function
 * We construct a buffer that holds the state of all 24 rounds sequentially.
 * Each round consists of 200 bytes, the total buffer we should return is 4.8 kB * number of instances
 */
void *keccacheck_init(const uint8_t *ptr,
                      uintptr_t len);

/**
 * Frees memory allocated by `keccak_init`.
 *
 * # Safety
 * The pointer must be a valid pointer to a `KeccakInstance` that was created by `keccak_init`.
 * It must not have been freed already.
 */
void keccacheck_free(void *ptr, uintptr_t len);

/**
 * Constructs a GKR proof of a KeccakF permutation
 *
 * Takes a pointer to a u8 slice representing the input to a KeccakF function
 * and returns the proof in the form of three pointers:
 * 1) Pointer to the field elements represetning the proof
 * 2) Pointer to the input to the function
 * 3) Pointer to the output of the function
 *
 * # Safety
 *
 * This function is marked `unsafe` because it dereferences a raw pointer and constructs
 * a slice from it using `std::slice::from_raw_parts`. The caller **must** ensure the following:
 *
 * - `ptr` must be non-null and properly aligned for `u8`.
 * - `ptr` must point to a valid memory region that contains at least `instances * 8 * 25` contiguous `u8` elements.
 * - The memory region starting at `ptr` and extending for `len * 8 * 25* size_of::<u8>()` bytes must be valid
 *   for reads for the lifetime of the call.
 * - The memory must not be mutated by other threads while this function is executing.
 *
 * Violating any of these requirements results in **undefined behavior**.
 *
 */
void *keccacheck_prove(const uint8_t *ptr,
                       uintptr_t instances);

void keccacheck_proof_free(void *proof_ptr, void *input_ptr, void *output_ptr, uintptr_t instances);
