#include <stdio.h>
#include <stdlib.h>
#include "mlkem/mlkem.h"

#define RUNS 10000

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
    return exchange_run("mlkem512", mlkem512_exchange) == 0 &&
                   exchange_run("mlkem768", mlkem768_exchange) == 0 &&
                   exchange_run("mlkem1024", mlkem1024_exchange) == 0 &&
                   exchange_run("tempo512", tempo512_exchange) == 0 &&
                   exchange_run("tempo768", tempo768_exchange) == 0 &&
                   exchange_run("tempo1024", tempo1024_exchange) == 0
               ? EXIT_SUCCESS
               : EXIT_FAILURE;
}
