#include <stdio.h>
#include <stdlib.h>
#ifdef MLK_CONFIG_USE_OPENSSL
#include <openssl/opensslv.h>
#endif
#include "mlkem/mlkem.h"

#define RUNS 100000

static int test_run(const char *name, int f())
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
        printf("ok\n");
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
#ifdef MLK_CONFIG_USE_OPENSSL
    printf("%s\n", OPENSSL_VERSION_TEXT);
#endif
    printf("N = %d\n", RUNS);
    int ok = 1;
    ok = test_run("mlkem512_exchange", mlkem512_test_exchange) == 0 && ok;
    ok = test_run("mlkem768_exchange", mlkem768_test_exchange) == 0 && ok;
    ok = test_run("mlkem1024_exchange", mlkem1024_test_exchange) == 0 && ok;
    ok = test_run("tempo512_exchange_correct", tempo512_test_exchange_correct) == 0 && ok;
    ok = test_run("tempo512_exchange_incorrect", tempo512_test_exchange_incorrect) == 0 && ok;
    ok = test_run("tempo768_exchange_correct", tempo768_test_exchange_correct) == 0 && ok;
    ok = test_run("tempo768_exchange_incorrect", tempo768_test_exchange_incorrect) == 0 && ok;
    ok = test_run("tempo1024_exchange_correct", tempo1024_test_exchange_correct) == 0 && ok;
    ok = test_run("tempo1024_exchange_incorrect", tempo1024_test_exchange_incorrect) == 0 && ok;
    ok = test_run("tempo512_gen_vector", tempo512_test_gen_vector) == 0 && ok;
    ok = test_run("tempo768_gen_vector", tempo768_test_gen_vector) == 0 && ok;
    ok = test_run("tempo1024_gen_vector", tempo1024_test_gen_vector) == 0 && ok;
    ok = test_run("tempo512_gen_matrix", tempo512_test_gen_matrix) == 0 && ok;
    ok = test_run("tempo768_gen_matrix", tempo768_test_gen_matrix) == 0 && ok;
    ok = test_run("tempo1024_gen_matrix", tempo1024_test_gen_matrix) == 0 && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
