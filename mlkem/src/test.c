#include <string.h>
#include <stdio.h>
#include <openssl/rand.h>
#include "test.h"
#include "indcpa.h"
#include "kem.h"
#include "tempo.h"

MLK_EXTERNAL_API
int mlk_test_exchange()
{
    uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    if (mlk_kem_keypair(pk, sk) != 0)
    {
        return -1;
    }
    uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM_SSBYTES];
    if (mlk_kem_enc(ct, ss1, pk) != 0)
    {
        return -1;
    }
    uint8_t ss2[MLKEM_SSBYTES];
    if (mlk_kem_dec(ss2, ct, sk) != 0)
    {
        return -1;
    }
    if (memcmp(ss1, ss2, MLKEM_SSBYTES) != 0)
    {
        return -1;
    }
    return 0;
}

MLK_EXTERNAL_API
int mlk_test_tempo_exchange()
{
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(sid, TEMPO_LEN_PWD);
    uint8_t pk1[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    uint8_t apk[TEMPO_LEN_APK];
    if (mlk_tempo_keygen(pk1, sk, apk, sid, pwd) != 0)
    {
        return -1;
    }
    uint8_t pk2[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
    uint8_t ek1[MLKEM_SSBYTES];
    if (mlk_tempo_encaps(
            pk2,
            ct,
            ek1,
            sid,
            pwd,
            apk) != 0)
    {
        return -1;
    }
    uint8_t ek2[MLKEM_SSBYTES];
    if (mlk_tempo_decaps(ek2, sk, ct) != 0)
    {
        return -1;
    }
    uint8_t tag_a_a[TEMPO_LEN_TAG];
    uint8_t tag_b_a[TEMPO_LEN_TAG];
    uint8_t shared_secret_a[TEMPO_LEN_SHARED_SECRET];
    mlk_tempo_confirm(
        tag_a_a,
        tag_b_a,
        shared_secret_a,
        sid,
        pwd,
        apk,
        ct,
        pk1,
        ek2);
    uint8_t tag_a_b[TEMPO_LEN_TAG];
    uint8_t tag_b_b[TEMPO_LEN_TAG];
    uint8_t shared_secret_b[TEMPO_LEN_SHARED_SECRET];
    mlk_tempo_confirm(
        tag_a_b,
        tag_b_b,
        shared_secret_b,
        sid,
        pwd,
        apk,
        ct,
        pk2,
        ek1);
    if (mlk_tempo_verify(tag_a_a, tag_a_b) != 0)
    {
        return -1;
    }
    if (mlk_tempo_verify(tag_a_a, tag_a_b) != 0)
    {
        return -1;
    }
    if (memcmp(shared_secret_a, shared_secret_b, TEMPO_LEN_SHARED_SECRET) != 0)
    {
        return -1;
    }
    return 0;
}

MLK_EXTERNAL_API
int mlk_test_tempo_gen_matrix()
{
    uint8_t seed[MLKEM_SYMBYTES];
    RAND_bytes(seed, MLKEM_SYMBYTES);
    mlk_polymat a1;
    mlk_gen_matrix(&a1, seed, 0);
    mlk_polymat a2;
    mlk_tempo_gen_matrix(&a2, seed, 0);
    for (int i = 0; i < MLKEM_K; i++)
    {
        for (int j = 0; j < MLKEM_K; j++)
        {
            for (int k = 0; k < MLKEM_N; k++)
            {
                if (a1.vec[i].vec[j].coeffs[k] != a2.vec[i].vec[j].coeffs[k])
                {
                    return -1;
                }
            }
        }
    }
    return 0;
}
