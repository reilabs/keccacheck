#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define COLUMNS 5

#define ROWS 5

#define STATE (COLUMNS * ROWS)

void *keccacheck_init(const uint8_t *ptr, uintptr_t len);

/**
 * Frees memory allocated by `keccak_init`.
 *
 * # Safety
 * The pointer must be a valid pointer to a `KeccakInstance` that was created by `keccak_init`.
 * It must not have been freed already.
 */
void keccacheck_free(void *ptr);
