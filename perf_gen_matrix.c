#include <stdlib.h>
#include <stdio.h>
#include "mlkem/mlkem.h"

#define RUNS 10000000

int main()
{
    printf("%d\n", RUNS);
    for (int level = 1; level <= 5; level += 2)
    {
        for (int i = 0; i < RUNS; i++)
        {
            uint64_t ns;
            switch (level)
            {
            case 1:
                ns = mlkem512_perf_gen_matrix();
                break;
            case 3:
                ns = mlkem768_perf_gen_matrix();
                break;
            case 5:
                ns = mlkem1024_perf_gen_matrix();
                break;
            }
            printf("%ld\n", ns);
        }
    }
    return EXIT_SUCCESS;
}
