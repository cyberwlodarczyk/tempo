#include <string.h>
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

#define test_tempo_exchange MLK_ADD_PARAM_SET(test_tempo_exchange)
static int test_tempo_exchange(uint8_t *pwd1, uint8_t *pwd2)
{
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pk1[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    uint8_t apk[TEMPO_LEN_APK];
    if (mlk_tempo_keygen(pk1, apk, sk, sid, pwd1) != 0)
    {
        return -1;
    }
    uint8_t ss2[TEMPO_LEN_SHARED_SECRET];
    uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
    uint8_t tag[TEMPO_LEN_TAG];
    if (mlk_tempo_encaps(ss2, ct, tag, apk, sid, pwd2) != 0)
    {
        return -1;
    }
    uint8_t ss1[TEMPO_LEN_SHARED_SECRET];
    if (mlk_tempo_decaps(ss1, pk1, apk, sk, ct, tag, sid, pwd1) != 0)
    {
        return -1;
    }
    if (memcmp(ss1, ss2, TEMPO_LEN_SHARED_SECRET) != 0)
    {
        return -1;
    }
    return 0;
}

MLK_EXTERNAL_API
int mlk_test_tempo_exchange_correct()
{
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    return test_tempo_exchange(pwd, pwd);
}

MLK_EXTERNAL_API
int mlk_test_tempo_exchange_incorrect()
{
    uint8_t pwd1[TEMPO_LEN_PWD];
    RAND_bytes(pwd1, TEMPO_LEN_PWD);
    uint8_t pwd2[TEMPO_LEN_PWD];
    RAND_bytes(pwd2, TEMPO_LEN_PWD);
    return test_tempo_exchange(pwd1, pwd2) == 0 ? -1 : 0;
}

MLK_EXTERNAL_API
int mlk_test_tempo_gen_vector()
{
    uint8_t seed[MLKEM_SYMBYTES];
    RAND_bytes(seed, MLKEM_SYMBYTES);
    mlk_polyvec v1;
    mlk_gen_vector(&v1, seed, 0);
    mlk_polyvec v2;
    mlk_tempo_gen_vector(&v2, seed, 0);
    mlk_polyvec_permute_bitrev_to_custom(&v2);
    for (int j = 0; j < MLKEM_K; j++)
    {
        for (int k = 0; k < MLKEM_N; k++)
        {
            if (v1.vec[j].coeffs[k] != v2.vec[j].coeffs[k])
            {
                return -1;
            }
        }
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
    mlk_polymat_permute_bitrev_to_custom(&a2);
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

#undef test_tempo_exchange
