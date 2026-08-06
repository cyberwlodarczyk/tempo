#include "common.h"
#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
#if defined(MLK_CONFIG_USE_OPENSSL) && !defined(MLK_CONFIG_FORCE_GETRANDOM)
#include <openssl/rand.h>
#else
#include <sys/random.h>
#endif
#include "randombytes.h"

MLK_INTERNAL_API
int mlk_randombytes(uint8_t *out, size_t outlen)
{
#if defined(MLK_CONFIG_USE_OPENSSL) && !defined(MLK_CONFIG_FORCE_GETRANDOM)
    return RAND_priv_bytes(out, (int)outlen) == 1 ? 0 : MLK_ERR_RNG_FAIL;
#else
    return getrandom(out, outlen, GRND_NONBLOCK) != -1 ? 0 : MLK_ERR_RNG_FAIL;
#endif
}

#endif
