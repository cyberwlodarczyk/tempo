#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "mlkem/mlkem.h"

#define RUNS 10000

int exchange_mlkem512()
{
    uint8_t pk[MLKEM512_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM512_LEN_SECRET_KEY];
    if (mlkem512_keypair(pk, sk) != 0)
    {
        return -1;
    }
    uint8_t ct[MLKEM512_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM512_LEN_SHARED_SECRET];
    if (mlkem512_enc(ct, ss1, pk) != 0)
    {
        return -1;
    }
    uint8_t ss2[MLKEM512_LEN_SHARED_SECRET];
    if (mlkem512_dec(ss2, ct, sk) != 0)
    {
        return -1;
    }
    if (memcmp(ss1, ss2, MLKEM512_LEN_SHARED_SECRET) != 0)
    {
        return -1;
    }
    return 0;
}

int exchange_mlkem768()
{
    uint8_t pk[MLKEM768_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM768_LEN_SECRET_KEY];
    if (mlkem768_keypair(pk, sk) != 0)
    {
        return -1;
    }
    uint8_t ct[MLKEM768_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM768_LEN_SHARED_SECRET];
    if (mlkem768_enc(ct, ss1, pk) != 0)
    {
        return -1;
    }
    uint8_t ss2[MLKEM768_LEN_SHARED_SECRET];
    if (mlkem768_dec(ss2, ct, sk) != 0)
    {
        return -1;
    }
    if (memcmp(ss1, ss2, MLKEM768_LEN_SHARED_SECRET) != 0)
    {
        return -1;
    }
    return 0;
}

int exchange_mlkem1024()
{
    uint8_t pk[MLKEM1024_LEN_PUBLIC_KEY];
    uint8_t sk[MLKEM1024_LEN_SECRET_KEY];
    if (mlkem1024_keypair(pk, sk) != 0)
    {
        return -1;
    }
    uint8_t ct[MLKEM1024_LEN_CIPHERTEXT];
    uint8_t ss1[MLKEM1024_LEN_SHARED_SECRET];
    if (mlkem1024_enc(ct, ss1, pk) != 0)
    {
        return -1;
    }
    uint8_t ss2[MLKEM1024_LEN_SHARED_SECRET];
    if (mlkem1024_dec(ss2, ct, sk) != 0)
    {
        return -1;
    }
    if (memcmp(ss1, ss2, MLKEM1024_LEN_SHARED_SECRET) != 0)
    {
        return -1;
    }
    return 0;
}

int exchange_run(const char *name, int f())
{
    printf("%s: ", name);
    fflush(stdout);
    int fail = 0;
    for (int i = 0; i < RUNS; i++)
    {
        if (f() != 0)
        {
            fail++;
        }
    }
    if (fail == 0)
    {
        printf("ok (%d/%d)\n", RUNS, RUNS);
        return 0;
    }
    else
    {
        printf("fail (%d/%d)\n", RUNS - fail, RUNS);
        return -1;
    }
}

int main()
{
    return exchange_run("mlkem512", exchange_mlkem512) == 0 &&
                   exchange_run("mlkem768", exchange_mlkem768) == 0 &&
                   exchange_run("mlkem1024", exchange_mlkem1024) == 0
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
