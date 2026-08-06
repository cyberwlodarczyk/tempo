#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#ifdef MLK_CONFIG_USE_OPENSSL
#include <openssl/opensslv.h>
#endif
#include "mlkem/mlkem.h"

#define WARMUP_RUNS 1000
#define RUNS 100000

static void perf_run(const char *name, uint64_t f())
{
    printf("%s: ", name);
    fflush(stdout);
    uint64_t total = 0;
    for (int i = 0; i < WARMUP_RUNS + RUNS; i++)
    {
        uint64_t ns = f();
        if (ns == 0)
        {
            printf("fail\n");
            return;
        }
        if (i >= WARMUP_RUNS)
        {
            total += ns;
        }
    }
    uint64_t avg = total / RUNS;
    printf("%.2fµs\n", (double)avg / 1000);
}

int main()
{
#ifdef MLK_CONFIG_USE_OPENSSL
    printf("%s\n", OPENSSL_VERSION_TEXT);
#endif
    printf("N warmup = %d\n", WARMUP_RUNS);
    printf("N        = %d\n", RUNS);
    perf_run("rand_32_bytes", mlkem_perf_rand_32_bytes);
    perf_run("mlkem512_gen_vector", mlkem512_perf_gen_vector);
    perf_run("mlkem512_gen_matrix", mlkem512_perf_gen_matrix);
    perf_run("mlkem512_keypair", mlkem512_perf_keypair);
    perf_run("mlkem512_enc", mlkem512_perf_enc);
    perf_run("mlkem512_dec", mlkem512_perf_dec);
    perf_run("mlkem768_gen_vector", mlkem768_perf_gen_vector);
    perf_run("mlkem768_gen_matrix", mlkem768_perf_gen_matrix);
    perf_run("mlkem768_keypair", mlkem768_perf_keypair);
    perf_run("mlkem768_enc", mlkem768_perf_enc);
    perf_run("mlkem768_dec", mlkem768_perf_dec);
    perf_run("mlkem1024_gen_vector", mlkem1024_perf_gen_vector);
    perf_run("mlkem1024_gen_matrix", mlkem1024_perf_gen_matrix);
    perf_run("mlkem1024_keypair", mlkem1024_perf_keypair);
    perf_run("mlkem1024_enc", mlkem1024_perf_enc);
    perf_run("mlkem1024_dec", mlkem1024_perf_dec);
    perf_run("tempo512_gen_vector", tempo512_perf_gen_vector);
    perf_run("tempo512_gen_matrix", tempo512_perf_gen_matrix);
    perf_run("tempo512_keygen", tempo512_perf_keygen);
    perf_run("tempo512_encaps", tempo512_perf_encaps);
    perf_run("tempo512_decaps", tempo512_perf_decaps);
    perf_run("tempo768_gen_vector", tempo768_perf_gen_vector);
    perf_run("tempo768_gen_matrix", tempo768_perf_gen_matrix);
    perf_run("tempo768_keygen", tempo768_perf_keygen);
    perf_run("tempo768_encaps", tempo768_perf_encaps);
    perf_run("tempo768_decaps", tempo768_perf_decaps);
    perf_run("tempo1024_gen_vector", tempo1024_perf_gen_vector);
    perf_run("tempo1024_gen_matrix", tempo1024_perf_gen_matrix);
    perf_run("tempo1024_keygen", tempo1024_perf_keygen);
    perf_run("tempo1024_encaps", tempo1024_perf_encaps);
    perf_run("tempo1024_decaps", tempo1024_perf_decaps);
    return EXIT_SUCCESS;
}
