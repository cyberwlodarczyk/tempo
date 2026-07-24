#include <stdio.h>
#include <stdlib.h>
#include "mlkem/mlkem.h"

#define RUNS 10000

int test_run(const char *name, int f())
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
    int ok = 1;
    ok = test_run("mlkem512_exchange", mlkem512_test_exchange) == 0 && ok;
    ok = test_run("mlkem768_exchange", mlkem768_test_exchange) == 0 && ok;
    ok = test_run("mlkem1024_exchange", mlkem1024_test_exchange) == 0 && ok;
    ok = test_run("tempo512_exchange", tempo512_test_exchange) == 0 && ok;
    ok = test_run("tempo768_exchange", tempo768_test_exchange) == 0 && ok;
    ok = test_run("tempo1024_exchange", tempo1024_test_exchange) == 0 && ok;
    ok = test_run("tempo512_gen_matrix", tempo512_test_gen_matrix) == 0 && ok;
    ok = test_run("tempo768_gen_matrix", tempo768_test_gen_matrix) == 0 && ok;
    ok = test_run("tempo1024_gen_matrix", tempo1024_test_gen_matrix) == 0 && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
