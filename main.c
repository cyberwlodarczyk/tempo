#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mlkem_native_all.c"
#define MLK_CONFIG_CONSTANTS_ONLY
#include <mlkem_native.h>
#include "rng/randombytes.h"

#define CHECK(x)                                                    \
    do                                                              \
    {                                                               \
        int rc;                                                     \
        rc = (x);                                                   \
        if (!rc)                                                    \
        {                                                           \
            fprintf(stderr, "ERROR (%s,%d)\n", __FILE__, __LINE__); \
            return 1;                                               \
        }                                                           \
    } while (0)

static int test_keys_mlkem512(void)
{
    uint8_t pk[MLKEM512_PUBLICKEYBYTES];
    uint8_t sk[MLKEM512_SECRETKEYBYTES];
    uint8_t ct[MLKEM512_CIPHERTEXTBYTES];
    uint8_t key_a[MLKEM512_BYTES];
    uint8_t key_b[MLKEM512_BYTES];
    CHECK(mlkem512_keypair(pk, sk) == 0);
    CHECK(mlkem512_enc(ct, key_b, pk) == 0);
    CHECK(mlkem512_dec(key_a, ct, sk) == 0);
    CHECK(memcmp(key_a, key_b, MLKEM512_BYTES) == 0);
    printf("Shared secret: ");
    {
        size_t i;
        for (i = 0; i < sizeof(key_a); i++)
        {
            printf("%02x", key_a[i]);
        }
    }
    printf("\n");
    printf("[MLKEM-512] OK\n");
    return 0;
}

static int test_keys_mlkem768(void)
{
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t key_a[MLKEM768_BYTES];
    uint8_t key_b[MLKEM768_BYTES];
    CHECK(mlkem768_keypair(pk, sk) == 0);
    CHECK(mlkem768_enc(ct, key_b, pk) == 0);
    CHECK(mlkem768_dec(key_a, ct, sk) == 0);
    CHECK(memcmp(key_a, key_b, MLKEM768_BYTES) == 0);
    printf("Shared secret: ");
    {
        size_t i;
        for (i = 0; i < sizeof(key_a); i++)
        {
            printf("%02x", key_a[i]);
        }
    }
    printf("\n");
    printf("[MLKEM-768] OK\n");
    return 0;
}

static int test_keys_mlkem1024(void)
{
    uint8_t pk[MLKEM1024_PUBLICKEYBYTES];
    uint8_t sk[MLKEM1024_SECRETKEYBYTES];
    uint8_t ct[MLKEM1024_CIPHERTEXTBYTES];
    uint8_t key_a[MLKEM1024_BYTES];
    uint8_t key_b[MLKEM1024_BYTES];
    CHECK(mlkem1024_keypair(pk, sk) == 0);
    CHECK(mlkem1024_enc(ct, key_b, pk) == 0);
    CHECK(mlkem1024_dec(key_a, ct, sk) == 0);
    CHECK(memcmp(key_a, key_b, MLKEM1024_BYTES) == 0);
    printf("Shared secret: ");
    {
        size_t i;
        for (i = 0; i < sizeof(key_a); i++)
        {
            printf("%02x", key_a[i]);
        }
    }
    printf("\n");
    printf("[MLKEM-1024] OK\n");
    return 0;
}

int main(void)
{
    if (test_keys_mlkem512() != 0)
    {
        return 1;
    }
    if (test_keys_mlkem768() != 0)
    {
        return 1;
    }
    if (test_keys_mlkem1024() != 0)
    {
        return 1;
    }
    return 0;
}
