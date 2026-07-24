#ifndef MLK_TEST_H
#define MLK_TEST_H

#include "common.h"

#define mlk_test_exchange MLK_NAMESPACE_K(test_exchange)
MLK_EXTERNAL_API
int mlk_test_exchange();

#define mlk_test_tempo_exchange MLK_TEMPO_NAMESPACE_K(test_exchange)
MLK_EXTERNAL_API
int mlk_test_tempo_exchange();

#define mlk_test_tempo_gen_matrix MLK_TEMPO_NAMESPACE_K(test_gen_matrix)
MLK_EXTERNAL_API
int mlk_test_tempo_gen_matrix();

#endif
