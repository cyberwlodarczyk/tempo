#include "common.h"
#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
#include <openssl/rand.h>
#include "randombytes.h"

MLK_INTERNAL_API
int mlk_randombytes(uint8_t *out, size_t outlen)
{
    return RAND_priv_bytes(out, (int)outlen) == 1 ? 0 : MLK_ERR_RNG_FAIL;
}

#endif
