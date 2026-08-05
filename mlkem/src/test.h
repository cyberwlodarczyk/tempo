#ifndef MLK_TEST_H
#define MLK_TEST_H

#include "common.h"

#define mlk_test_exchange MLK_NAMESPACE_K(test_exchange)
MLK_EXTERNAL_API
int mlk_test_exchange(void);

#define mlk_test_tempo_exchange MLK_TEMPO_NAMESPACE_K(test_exchange)
MLK_EXTERNAL_API
int mlk_test_tempo_exchange(void);

#define mlk_test_tempo_exchange_correct MLK_TEMPO_NAMESPACE_K(test_exchange_correct)
MLK_EXTERNAL_API
int mlk_test_tempo_exchange_correct(void);

#define mlk_test_tempo_exchange_incorrect MLK_TEMPO_NAMESPACE_K(test_exchange_incorrect)
MLK_EXTERNAL_API
int mlk_test_tempo_exchange_incorrect(void);

#define mlk_test_tempo_gen_vector MLK_TEMPO_NAMESPACE_K(test_gen_vector)
MLK_EXTERNAL_API
int mlk_test_tempo_gen_vector(void);

#define mlk_test_tempo_gen_matrix MLK_TEMPO_NAMESPACE_K(test_gen_matrix)
MLK_EXTERNAL_API
int mlk_test_tempo_gen_matrix(void);

#endif
