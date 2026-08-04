#define _POSIX_C_SOURCE 199309L
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <openssl/rand.h>
#include "perf.h"
#include "indcpa.h"
#include "kem.h"
#include "tempo.h"
#include "randombytes.h"

#define time_ns MLK_ADD_PARAM_SET(time_ns)
static uint64_t time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#ifdef MLK_CONFIG_MULTILEVEL_WITH_SHARED
MLK_EXTERNAL_API
uint64_t mlk_perf_randombytes_32()
{
    uint8_t seed[32];
    uint64_t start = time_ns();
    if (mlk_randombytes(seed, 32) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}
#endif

MLK_EXTERNAL_API
uint64_t mlk_perf_polyvec_sub()
{
    uint8_t seed1[MLKEM_SYMBYTES];
    RAND_bytes(seed1, MLKEM_SYMBYTES);
    mlk_polyvec v1;
    mlk_gen_vector(&v1, seed1, 0);
    uint8_t seed2[MLKEM_SYMBYTES];
    RAND_bytes(seed2, MLKEM_SYMBYTES);
    mlk_polyvec v2;
    mlk_gen_vector(&v2, seed1, 0);
    uint64_t start = time_ns();
    mlk_polyvec_sub(&v1, &v2);
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_polyvec_sub_mask()
{
    uint8_t seed1[MLKEM_SYMBYTES];
    RAND_bytes(seed1, MLKEM_SYMBYTES);
    mlk_polyvec v1;
    mlk_gen_vector(&v1, seed1, 0);
    uint8_t seed2[MLKEM_SYMBYTES];
    RAND_bytes(seed2, MLKEM_SYMBYTES);
    mlk_polyvec v2;
    mlk_gen_vector(&v2, seed1, 0);
    uint8_t seed3[MLKEM_SYMBYTES];
    RAND_bytes(seed3, MLKEM_SYMBYTES);
    mlk_polyvec v3;
    mlk_gen_vector(&v3, seed1, 0);
    uint64_t start = time_ns();
    mlk_polyvec_sub_mask(&v1, &v2, &v3, 0);
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_gen_vector()
{
    uint8_t seed[MLKEM_SYMBYTES];
    RAND_bytes(seed, MLKEM_SYMBYTES);
    mlk_polyvec v;
    uint64_t start = time_ns();
    mlk_gen_vector(&v, seed, 0);
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_gen_matrix()
{
    uint8_t seed[MLKEM_SYMBYTES];
    RAND_bytes(seed, MLKEM_SYMBYTES);
    mlk_polymat a;
    uint64_t start = time_ns();
    mlk_gen_matrix(&a, seed, 0);
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_keypair()
{
    uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    uint64_t start = time_ns();
    if (mlk_kem_keypair(pk, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_enc()
{
    uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    if (mlk_kem_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
    uint8_t ss[MLKEM_SSBYTES];
    uint64_t start = time_ns();
    if (mlk_kem_enc(ct, ss, pk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_dec()
{
    uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    if (mlk_kem_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM_SSBYTES];
    if (mlk_kem_enc(ct, ss1, pk) != 0)
    {
        return 0;
    }
    uint64_t start = time_ns();
    uint8_t ss2[MLKEM_SSBYTES];
    if (mlk_kem_dec(ss2, ct, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_gen_vector()
{
    uint8_t seed[MLKEM_SYMBYTES];
    RAND_bytes(seed, MLKEM_SYMBYTES);
    mlk_polyvec v;
    uint64_t start = time_ns();
    mlk_tempo_gen_vector(&v, seed, 0);
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_gen_matrix()
{
    uint8_t seed[MLKEM_SYMBYTES];
    RAND_bytes(seed, MLKEM_SYMBYTES);
    mlk_polymat a;
    uint64_t start = time_ns();
    mlk_tempo_gen_matrix(&a, seed, 0);
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_keygen()
{
    uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t apk[TEMPO_LEN_APK];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    uint64_t start = time_ns();
    if (mlk_tempo_keygen(pk, apk, sk, sid, pwd) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_encaps()
{
    uint8_t pk1[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t apk[TEMPO_LEN_APK];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    if (mlk_tempo_keygen(pk1, apk, sk, sid, pwd) != 0)
    {
        return 0;
    }
    uint8_t ss[TEMPO_LEN_SHARED_SECRET];
    uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
    uint8_t tag[TEMPO_LEN_TAG];
    uint64_t start = time_ns();
    if (mlk_tempo_encaps(ss, ct, tag, apk, sid, pwd) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_decaps()
{
    uint8_t pk1[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t apk[TEMPO_LEN_APK];
    uint8_t sk[MLKEM_INDCCA_LEN_SECRET_KEY];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    if (mlk_tempo_keygen(pk1, apk, sk, sid, pwd) != 0)
    {
        return 0;
    }
    uint8_t ss1[TEMPO_LEN_SHARED_SECRET];
    uint8_t ct[MLKEM_INDCCA_LEN_CIPHERTEXT];
    uint8_t tag[TEMPO_LEN_TAG];
    if (mlk_tempo_encaps(ss1, ct, tag, apk, sid, pwd) != 0)
    {
        return 0;
    }
    uint8_t ss2[TEMPO_LEN_SHARED_SECRET];
    uint64_t start = time_ns();
    if (mlk_tempo_decaps(ss2, pk1, apk, sk, ct, tag, sid, pwd) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

#undef time_ns
