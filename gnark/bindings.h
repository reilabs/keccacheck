#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

uint8_t *keccacheck_init(const uint8_t *ptr, uintptr_t len, uintptr_t *out_len);

/**
 * Frees memory allocated by keccacheck_init.
 *
 * # Safety
 * The pointer and length must be exactly as returned by keccacheck_init and must not have been freed already.
 */
void keccacheck_free(uint8_t *ptr,
                     uintptr_t len);
