#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include "randombytes.h"

int randombytes(uint8_t *buf, size_t n)
{
    return RAND_priv_bytes(buf, (int)n) == 1 ? 0 : -1;
}
