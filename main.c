#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mlkem/mlkem.h"

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
    uint8_t pk[MLKEM512_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM512_LEN_SECRET_KEY];
    uint8_t ct[MLKEM512_LEN_CIPHERTEXT];
    uint8_t key_a[MLKEM512_LEN_SHARED_SECRET];
    uint8_t key_b[MLKEM512_LEN_SHARED_SECRET];
    CHECK(mlkem512_keypair(pk, sk) == 0);
    CHECK(mlkem512_enc(ct, key_b, pk) == 0);
    CHECK(mlkem512_dec(key_a, ct, sk) == 0);
    CHECK(memcmp(key_a, key_b, MLKEM512_LEN_SHARED_SECRET) == 0);
    print_secret(key_a, sizeof(key_a));
    printf("[MLKEM-512] OK\n");
    return 0;
}

static int test_keys_mlkem768(void)
{
    uint8_t pk[MLKEM768_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM768_LEN_SECRET_KEY];
    uint8_t ct[MLKEM768_LEN_CIPHERTEXT];
    uint8_t key_a[MLKEM768_LEN_SHARED_SECRET];
    uint8_t key_b[MLKEM768_LEN_SHARED_SECRET];
    CHECK(mlkem768_keypair(pk, sk) == 0);
    CHECK(mlkem768_enc(ct, key_b, pk) == 0);
    CHECK(mlkem768_dec(key_a, ct, sk) == 0);
    CHECK(memcmp(key_a, key_b, MLKEM768_LEN_SHARED_SECRET) == 0);
    print_secret(key_a, sizeof(key_a));
    printf("[MLKEM-768] OK\n");
    return 0;
}

static int test_keys_mlkem1024(void)
{
    uint8_t pk[MLKEM1024_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM1024_LEN_SECRET_KEY];
    uint8_t ct[MLKEM1024_LEN_CIPHERTEXT];
    uint8_t key_a[MLKEM1024_LEN_SHARED_SECRET];
    uint8_t key_b[MLKEM1024_LEN_SHARED_SECRET];
    CHECK(mlkem1024_keypair(pk, sk) == 0);
    CHECK(mlkem1024_enc(ct, key_b, pk) == 0);
    CHECK(mlkem1024_dec(key_a, ct, sk) == 0);
    CHECK(memcmp(key_a, key_b, MLKEM1024_LEN_SHARED_SECRET) == 0);
    print_secret(key_a, sizeof(key_a));
    printf("[MLKEM-1024] OK\n");
    return 0;
}

static int test_keys_tempo512(void)
{
    uint8_t sid[TEMPO_LEN_SID];
    RAND_priv_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_priv_bytes(sid, TEMPO_LEN_PWD);
    uint8_t public_key_a[TEMPO512_LEN_PUBLIC_KEY];
    uint8_t secret_key[TEMPO512_LEN_SECRET_KEY];
    uint8_t apk[TEMPO512_LEN_APK];
    tempo512_keygen(public_key_a, secret_key, apk, sid, pwd);
    uint8_t public_key_b[TEMPO512_LEN_PUBLIC_KEY];
    uint8_t ciphertext[TEMPO512_LEN_CIPHERTEXT];
    uint8_t ephemeral_key_b[TEMPO512_LEN_EPHEMERAL_KEY];
    tempo512_encaps(
        public_key_b,
        ciphertext,
        ephemeral_key_b,
        sid,
        pwd,
        apk);
    uint8_t ephemeral_key_a[TEMPO512_LEN_EPHEMERAL_KEY];
    tempo512_decaps(ephemeral_key_a, secret_key, ciphertext);
    uint8_t tag_a_a[TEMPO512_LEN_TAG];
    uint8_t tag_b_a[TEMPO512_LEN_TAG];
    uint8_t shared_secret_a[TEMPO512_LEN_SHARED_SECRET];
    tempo512_confirm(
        tag_a_a,
        tag_b_a,
        shared_secret_a,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_a,
        ephemeral_key_a);
    uint8_t tag_a_b[TEMPO512_LEN_TAG];
    uint8_t tag_b_b[TEMPO512_LEN_TAG];
    uint8_t shared_secret_b[TEMPO512_LEN_SHARED_SECRET];
    tempo512_confirm(
        tag_a_b,
        tag_b_b,
        shared_secret_b,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_b,
        ephemeral_key_b);
    CHECK(tempo512_verify(tag_a_a, tag_a_b) == 0);
    CHECK(tempo512_verify(tag_a_a, tag_a_b) == 0);
    CHECK(memcmp(shared_secret_a, shared_secret_b, TEMPO512_LEN_SHARED_SECRET) == 0);
    print_secret(shared_secret_a, sizeof(shared_secret_a));
    printf("[TEMPO-512] OK\n");
    return 0;
}

static int test_keys_tempo768(void)
{
    uint8_t sid[TEMPO_LEN_SID];
    RAND_priv_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_priv_bytes(sid, TEMPO_LEN_PWD);
    uint8_t public_key_a[TEMPO768_LEN_PUBLIC_KEY];
    uint8_t secret_key[TEMPO768_LEN_SECRET_KEY];
    uint8_t apk[TEMPO768_LEN_APK];
    tempo768_keygen(public_key_a, secret_key, apk, sid, pwd);
    uint8_t public_key_b[TEMPO768_LEN_PUBLIC_KEY];
    uint8_t ciphertext[TEMPO768_LEN_CIPHERTEXT];
    uint8_t ephemeral_key_b[TEMPO768_LEN_EPHEMERAL_KEY];
    tempo768_encaps(
        public_key_b,
        ciphertext,
        ephemeral_key_b,
        sid,
        pwd,
        apk);
    uint8_t ephemeral_key_a[TEMPO768_LEN_EPHEMERAL_KEY];
    tempo768_decaps(ephemeral_key_a, secret_key, ciphertext);
    uint8_t tag_a_a[TEMPO768_LEN_TAG];
    uint8_t tag_b_a[TEMPO768_LEN_TAG];
    uint8_t shared_secret_a[TEMPO768_LEN_SHARED_SECRET];
    tempo768_confirm(
        tag_a_a,
        tag_b_a,
        shared_secret_a,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_a,
        ephemeral_key_a);
    uint8_t tag_a_b[TEMPO768_LEN_TAG];
    uint8_t tag_b_b[TEMPO768_LEN_TAG];
    uint8_t shared_secret_b[TEMPO768_LEN_SHARED_SECRET];
    tempo768_confirm(
        tag_a_b,
        tag_b_b,
        shared_secret_b,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_b,
        ephemeral_key_b);
    CHECK(tempo768_verify(tag_a_a, tag_a_b) == 0);
    CHECK(tempo768_verify(tag_a_a, tag_a_b) == 0);
    CHECK(memcmp(shared_secret_a, shared_secret_b, TEMPO768_LEN_SHARED_SECRET) == 0);
    print_secret(shared_secret_a, sizeof(shared_secret_a));
    printf("[TEMPO-768] OK\n");
    return 0;
}

static int test_keys_tempo1024(void)
{
    uint8_t sid[TEMPO_LEN_SID];
    RAND_priv_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_priv_bytes(sid, TEMPO_LEN_PWD);
    uint8_t public_key_a[TEMPO1024_LEN_PUBLIC_KEY];
    uint8_t secret_key[TEMPO1024_LEN_SECRET_KEY];
    uint8_t apk[TEMPO1024_LEN_APK];
    tempo1024_keygen(public_key_a, secret_key, apk, sid, pwd);
    uint8_t public_key_b[TEMPO1024_LEN_PUBLIC_KEY];
    uint8_t ciphertext[TEMPO1024_LEN_CIPHERTEXT];
    uint8_t ephemeral_key_b[TEMPO1024_LEN_EPHEMERAL_KEY];
    tempo1024_encaps(
        public_key_b,
        ciphertext,
        ephemeral_key_b,
        sid,
        pwd,
        apk);
    uint8_t ephemeral_key_a[TEMPO1024_LEN_EPHEMERAL_KEY];
    tempo1024_decaps(ephemeral_key_a, secret_key, ciphertext);
    uint8_t tag_a_a[TEMPO1024_LEN_TAG];
    uint8_t tag_b_a[TEMPO1024_LEN_TAG];
    uint8_t shared_secret_a[TEMPO1024_LEN_SHARED_SECRET];
    tempo1024_confirm(
        tag_a_a,
        tag_b_a,
        shared_secret_a,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_a,
        ephemeral_key_a);
    uint8_t tag_a_b[TEMPO1024_LEN_TAG];
    uint8_t tag_b_b[TEMPO1024_LEN_TAG];
    uint8_t shared_secret_b[TEMPO1024_LEN_SHARED_SECRET];
    tempo1024_confirm(
        tag_a_b,
        tag_b_b,
        shared_secret_b,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key_b,
        ephemeral_key_b);
    CHECK(tempo1024_verify(tag_a_a, tag_a_b) == 0);
    CHECK(tempo1024_verify(tag_a_a, tag_a_b) == 0);
    CHECK(memcmp(shared_secret_a, shared_secret_b, TEMPO1024_LEN_SHARED_SECRET) == 0);
    print_secret(shared_secret_a, sizeof(shared_secret_a));
    printf("[TEMPO-1024] OK\n");
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
    if (test_keys_tempo512() != 0)
    {
        return 1;
    }
    if (test_keys_tempo768() != 0)
    {
        return 1;
    }
    if (test_keys_tempo1024() != 0)
    {
        return 1;
    }
    return 0;
}
