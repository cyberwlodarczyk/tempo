#include <openssl/rand.h>
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

static void print_secret(uint8_t *buf, size_t n)
{
    printf("Shared secret: ");
    {
        size_t i;
        for (i = 0; i < n; i++)
        {
            printf("%02x", buf[i]);
        }
    }
    printf("\n");
}

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
    print_secret(key_a, sizeof(key_a));
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
    print_secret(key_a, sizeof(key_a));
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
    print_secret(key_a, sizeof(key_a));
    printf("[MLKEM-1024] OK\n");
    return 0;
}

static int test_keys_mlkem512_tempo(void)
{
    uint8_t sid[MLKEM_TEMPO_SIDBYTES];
    RAND_bytes(sid, MLKEM_TEMPO_SIDBYTES);
    uint8_t pwd[MLKEM_TEMPO_PWDBYTES];
    RAND_bytes(sid, MLKEM_TEMPO_PWDBYTES);
    uint8_t public_key_a[MLKEM512_PUBLICKEYBYTES];
    uint8_t secret_key[MLKEM512_SECRETKEYBYTES];
    uint8_t apk[MLKEM512_TEMPO_APKBYTES];
    mlkem512_tempo_keygen(public_key_a, secret_key, apk, sid, pwd);
    uint8_t public_key_b[MLKEM512_PUBLICKEYBYTES];
    uint8_t ciphertext[MLKEM512_CIPHERTEXTBYTES];
    uint8_t ephemeral_key_b[MLKEM_BYTES];
    mlkem512_tempo_encaps(
        public_key_b,
        ciphertext,
        ephemeral_key_b,
        sid,
        pwd,
        apk);
    uint8_t ephemeral_key_a[MLKEM_BYTES];
    mlkem512_tempo_decaps(ephemeral_key_a, secret_key, ciphertext);
    uint8_t tag_a_a[MLKEM512_TEMPO_TAGBYTES];
    uint8_t tag_b_a[MLKEM512_TEMPO_TAGBYTES];
    uint8_t shared_secret_a[MLKEM512_TEMPO_BYTES];
    mlkem512_tempo_confirm(
        tag_a_a,
        tag_b_a,
        shared_secret_a,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_a,
        ephemeral_key_a);
    uint8_t tag_a_b[MLKEM512_TEMPO_TAGBYTES];
    uint8_t tag_b_b[MLKEM512_TEMPO_TAGBYTES];
    uint8_t shared_secret_b[MLKEM512_TEMPO_BYTES];
    mlkem512_tempo_confirm(
        tag_a_b,
        tag_b_b,
        shared_secret_b,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_b,
        ephemeral_key_b);
    CHECK(mlkem512_tempo_verify(tag_a_a, tag_a_b) == 0);
    CHECK(mlkem512_tempo_verify(tag_a_a, tag_a_b) == 0);
    CHECK(memcmp(shared_secret_a, shared_secret_b, MLKEM512_TEMPO_BYTES) == 0);
    print_secret(shared_secret_a, sizeof(shared_secret_a));
    printf("[MLKEM-512-TEMPO] OK\n");
    return 0;
}

static int test_keys_mlkem768_tempo(void)
{
    uint8_t sid[MLKEM_TEMPO_SIDBYTES];
    RAND_bytes(sid, MLKEM_TEMPO_SIDBYTES);
    uint8_t pwd[MLKEM_TEMPO_PWDBYTES];
    RAND_bytes(sid, MLKEM_TEMPO_PWDBYTES);
    uint8_t public_key_a[MLKEM768_PUBLICKEYBYTES];
    uint8_t secret_key[MLKEM768_SECRETKEYBYTES];
    uint8_t apk[MLKEM768_TEMPO_APKBYTES];
    mlkem768_tempo_keygen(public_key_a, secret_key, apk, sid, pwd);
    uint8_t public_key_b[MLKEM768_PUBLICKEYBYTES];
    uint8_t ciphertext[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ephemeral_key_b[MLKEM_BYTES];
    mlkem768_tempo_encaps(
        public_key_b,
        ciphertext,
        ephemeral_key_b,
        sid,
        pwd,
        apk);
    uint8_t ephemeral_key_a[MLKEM_BYTES];
    mlkem768_tempo_decaps(ephemeral_key_a, secret_key, ciphertext);
    uint8_t tag_a_a[MLKEM768_TEMPO_TAGBYTES];
    uint8_t tag_b_a[MLKEM768_TEMPO_TAGBYTES];
    uint8_t shared_secret_a[MLKEM768_TEMPO_BYTES];
    mlkem768_tempo_confirm(
        tag_a_a,
        tag_b_a,
        shared_secret_a,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_a,
        ephemeral_key_a);
    uint8_t tag_a_b[MLKEM768_TEMPO_TAGBYTES];
    uint8_t tag_b_b[MLKEM768_TEMPO_TAGBYTES];
    uint8_t shared_secret_b[MLKEM768_TEMPO_BYTES];
    mlkem768_tempo_confirm(
        tag_a_b,
        tag_b_b,
        shared_secret_b,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_b,
        ephemeral_key_b);
    CHECK(mlkem768_tempo_verify(tag_a_a, tag_a_b) == 0);
    CHECK(mlkem768_tempo_verify(tag_a_a, tag_a_b) == 0);
    CHECK(memcmp(shared_secret_a, shared_secret_b, MLKEM768_TEMPO_BYTES) == 0);
    print_secret(shared_secret_a, sizeof(shared_secret_a));
    printf("[MLKEM-768-TEMPO] OK\n");
    return 0;
}

static int test_keys_mlkem1024_tempo(void)
{
    uint8_t sid[MLKEM_TEMPO_SIDBYTES];
    RAND_bytes(sid, MLKEM_TEMPO_SIDBYTES);
    uint8_t pwd[MLKEM_TEMPO_PWDBYTES];
    RAND_bytes(sid, MLKEM_TEMPO_PWDBYTES);
    uint8_t public_key_a[MLKEM1024_PUBLICKEYBYTES];
    uint8_t secret_key[MLKEM1024_SECRETKEYBYTES];
    uint8_t apk[MLKEM1024_TEMPO_APKBYTES];
    mlkem1024_tempo_keygen(public_key_a, secret_key, apk, sid, pwd);
    uint8_t public_key_b[MLKEM1024_PUBLICKEYBYTES];
    uint8_t ciphertext[MLKEM1024_CIPHERTEXTBYTES];
    uint8_t ephemeral_key_b[MLKEM_BYTES];
    mlkem1024_tempo_encaps(
        public_key_b,
        ciphertext,
        ephemeral_key_b,
        sid,
        pwd,
        apk);
    uint8_t ephemeral_key_a[MLKEM_BYTES];
    mlkem1024_tempo_decaps(ephemeral_key_a, secret_key, ciphertext);
    uint8_t tag_a_a[MLKEM1024_TEMPO_TAGBYTES];
    uint8_t tag_b_a[MLKEM1024_TEMPO_TAGBYTES];
    uint8_t shared_secret_a[MLKEM1024_TEMPO_BYTES];
    mlkem1024_tempo_confirm(
        tag_a_a,
        tag_b_a,
        shared_secret_a,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_a,
        ephemeral_key_a);
    uint8_t tag_a_b[MLKEM1024_TEMPO_TAGBYTES];
    uint8_t tag_b_b[MLKEM1024_TEMPO_TAGBYTES];
    uint8_t shared_secret_b[MLKEM1024_TEMPO_BYTES];
    mlkem1024_tempo_confirm(
        tag_a_b,
        tag_b_b,
        shared_secret_b,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_b,
        ephemeral_key_b);
    CHECK(mlkem1024_tempo_verify(tag_a_a, tag_a_b) == 0);
    CHECK(mlkem1024_tempo_verify(tag_a_a, tag_a_b) == 0);
    CHECK(memcmp(shared_secret_a, shared_secret_b, MLKEM1024_TEMPO_BYTES) == 0);
    print_secret(shared_secret_a, sizeof(shared_secret_a));
    printf("[MLKEM-1024-TEMPO] OK\n");
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
    if (test_keys_mlkem512_tempo() != 0)
    {
        return 1;
    }
    if (test_keys_mlkem768_tempo() != 0)
    {
        return 1;
    }
    if (test_keys_mlkem1024_tempo() != 0)
    {
        return 1;
    }
    return 0;
}
