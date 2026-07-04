#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include "randombytes.h"

int randombytes(uint8_t *buf, size_t n)
{
    RAND_bytes(buf, (int)n);
    return 0;
}
