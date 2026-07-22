#define _POSIX_C_SOURCE 199309L
#include <stdlib.h>
#undef _POSIX_C_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <openssl/rand.h>
#include "mlkem/mlkem.h"

#define RUNS 10000

uint64_t time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

uint64_t perf_mlkem512_keypair()
{
    uint8_t pk[MLKEM512_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM512_LEN_SECRET_KEY];
    uint64_t start = time_ns();
    if (mlkem512_keypair(pk, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem512_enc()
{
    uint8_t pk[MLKEM512_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM512_LEN_SECRET_KEY];
    if (mlkem512_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM512_LEN_CIPHERTEXT];
    uint8_t ss[MLKEM512_LEN_SHARED_SECRET];
    uint64_t start = time_ns();
    if (mlkem512_enc(ct, ss, pk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem512_dec()
{
    uint8_t pk[MLKEM512_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM512_LEN_SECRET_KEY];
    if (mlkem512_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM512_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM512_LEN_SHARED_SECRET];
    if (mlkem512_enc(ct, ss1, pk) != 0)
    {
        return 0;
    }
    uint8_t ss2[MLKEM512_LEN_SHARED_SECRET];
    uint64_t start = time_ns();
    if (mlkem512_dec(ss2, ct, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_tempo512_keygen()
{
    uint8_t pk[TEMPO512_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO512_LEN_SECRET_KEY];
    uint8_t apk[TEMPO512_LEN_APK];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    uint64_t start = time_ns();
    if (tempo512_keygen(pk, sk, apk, sid, pwd) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_tempo512_encaps()
{
    uint8_t pk1[TEMPO512_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO512_LEN_SECRET_KEY];
    uint8_t apk[TEMPO512_LEN_APK];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    if (tempo512_keygen(pk1, sk, apk, sid, pwd) != 0)
    {
        return 0;
    }
    uint8_t pk2[TEMPO512_LEN_PUBLIC_KEY];
    uint8_t ct[TEMPO512_LEN_CIPHERTEXT];
    uint8_t ek[TEMPO512_LEN_EPHEMERAL_KEY];
    uint64_t start = time_ns();
    if (tempo512_encaps(pk2, ct, ek, sid, pwd, apk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem768_keypair()
{
    uint8_t pk[MLKEM768_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM768_LEN_SECRET_KEY];
    uint64_t start = time_ns();
    if (mlkem768_keypair(pk, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem768_enc()
{
    uint8_t pk[MLKEM768_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM768_LEN_SECRET_KEY];
    if (mlkem768_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM768_LEN_CIPHERTEXT];
    uint8_t ss[MLKEM768_LEN_SHARED_SECRET];
    uint64_t start = time_ns();
    if (mlkem768_enc(ct, ss, pk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem768_dec()
{
    uint8_t pk[MLKEM768_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM768_LEN_SECRET_KEY];
    if (mlkem768_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM768_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM768_LEN_SHARED_SECRET];
    if (mlkem768_enc(ct, ss1, pk) != 0)
    {
        return 0;
    }
    uint8_t ss2[MLKEM768_LEN_SHARED_SECRET];
    uint64_t start = time_ns();
    if (mlkem768_dec(ss2, ct, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_tempo768_keygen()
{
    uint8_t pk[TEMPO768_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO768_LEN_SECRET_KEY];
    uint8_t apk[TEMPO768_LEN_APK];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    uint64_t start = time_ns();
    if (tempo768_keygen(pk, sk, apk, sid, pwd) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_tempo768_encaps()
{
    uint8_t pk1[TEMPO768_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO768_LEN_SECRET_KEY];
    uint8_t apk[TEMPO768_LEN_APK];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    if (tempo768_keygen(pk1, sk, apk, sid, pwd) != 0)
    {
        return 0;
    }
    uint8_t pk2[TEMPO768_LEN_PUBLIC_KEY];
    uint8_t ct[TEMPO768_LEN_CIPHERTEXT];
    uint8_t ek[TEMPO768_LEN_EPHEMERAL_KEY];
    uint64_t start = time_ns();
    if (tempo768_encaps(pk2, ct, ek, sid, pwd, apk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem1024_keypair()
{
    uint8_t pk[MLKEM1024_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM1024_LEN_SECRET_KEY];
    uint64_t start = time_ns();
    if (mlkem1024_keypair(pk, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem1024_enc()
{
    uint8_t pk[MLKEM1024_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM1024_LEN_SECRET_KEY];
    if (mlkem1024_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM1024_LEN_CIPHERTEXT];
    uint8_t ss[MLKEM1024_LEN_SHARED_SECRET];
    uint64_t start = time_ns();
    if (mlkem1024_enc(ct, ss, pk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_mlkem1024_dec()
{
    uint8_t pk[MLKEM1024_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM1024_LEN_SECRET_KEY];
    if (mlkem1024_keypair(pk, sk) != 0)
    {
        return 0;
    }
    uint8_t ct[MLKEM1024_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM1024_LEN_SHARED_SECRET];
    if (mlkem1024_enc(ct, ss1, pk) != 0)
    {
        return 0;
    }
    uint8_t ss2[MLKEM1024_LEN_SHARED_SECRET];
    uint64_t start = time_ns();
    if (mlkem1024_dec(ss2, ct, sk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_tempo1024_keygen()
{
    uint8_t pk[TEMPO1024_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO1024_LEN_SECRET_KEY];
    uint8_t apk[TEMPO1024_LEN_APK];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    uint64_t start = time_ns();
    if (tempo1024_keygen(pk, sk, apk, sid, pwd) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

uint64_t perf_tempo1024_encaps()
{
    uint8_t pk1[TEMPO1024_LEN_PUBLIC_KEY];
    uint8_t sk[TEMPO1024_LEN_SECRET_KEY];
    uint8_t apk[TEMPO1024_LEN_APK];
    uint8_t sid[TEMPO_LEN_SID];
    RAND_bytes(sid, TEMPO_LEN_SID);
    uint8_t pwd[TEMPO_LEN_PWD];
    RAND_bytes(pwd, TEMPO_LEN_PWD);
    if (tempo1024_keygen(pk1, sk, apk, sid, pwd) != 0)
    {
        return 0;
    }
    uint8_t pk2[TEMPO1024_LEN_PUBLIC_KEY];
    uint8_t ct[TEMPO1024_LEN_CIPHERTEXT];
    uint8_t ek[TEMPO1024_LEN_EPHEMERAL_KEY];
    uint64_t start = time_ns();
    if (tempo1024_encaps(pk2, ct, ek, sid, pwd, apk) != 0)
    {
        return 0;
    }
    return time_ns() - start;
}

void perf_run(const char *name, uint64_t f())
{
    printf("%s: ", name);
    fflush(stdout);
    uint64_t total = 0;
    for (int i = 0; i < RUNS; i++)
    {
        uint64_t ns = f();
        if (ns == 0)
        {
            printf("fail\n");
            return;
        }
        total += ns;
    }
    uint64_t avg = total / RUNS;
    printf("%.2fµs\n", (double)avg / 1000);
}

int main()
{
    perf_run("mlkem512_keypair", perf_mlkem512_keypair);
    perf_run("mlkem512_enc", perf_mlkem512_enc);
    perf_run("mlkem512_dec", perf_mlkem512_dec);
    perf_run("mlkem768_keypair", perf_mlkem768_keypair);
    perf_run("mlkem768_enc", perf_mlkem768_enc);
    perf_run("mlkem768_dec", perf_mlkem768_dec);
    perf_run("mlkem1024_keypair", perf_mlkem1024_keypair);
    perf_run("mlkem1024_enc", perf_mlkem1024_enc);
    perf_run("mlkem1024_dec", perf_mlkem1024_dec);
    perf_run("tempo512_keygen", perf_tempo512_keygen);
    perf_run("tempo512_encaps", perf_tempo512_encaps);
    perf_run("tempo768_keygen", perf_tempo768_keygen);
    perf_run("tempo768_encaps", perf_tempo768_encaps);
    perf_run("tempo1024_keygen", perf_tempo1024_keygen);
    perf_run("tempo1024_encaps", perf_tempo1024_encaps);
    return EXIT_SUCCESS;
}
