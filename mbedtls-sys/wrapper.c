#include "wrapper.h"

#define NAME(n) wrapper_##n
#define NAME_MBED(n) mbedtls_cipher_##n
#define WRAPPER(n, t) t NAME(n)(const mbedtls_cipher_context_t *ctx) { return NAME_MBED(n)(&ctx);  }


WRAPPER(get_iv_size, int)
WRAPPER(get_block_size, unsigned int)
WRAPPER(get_key_bitlen, int)