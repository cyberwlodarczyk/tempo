#ifndef MLK_PERF_H
#define MLK_PERF_H

#include "common.h"

#define mlk_perf_gen_matrix MLK_NAMESPACE_K(perf_gen_matrix)
MLK_EXTERNAL_API
uint64_t mlk_perf_gen_matrix();

#define mlk_perf_keypair MLK_NAMESPACE_K(perf_keypair)
MLK_EXTERNAL_API
uint64_t mlk_perf_keypair();

#define mlk_perf_enc MLK_NAMESPACE_K(perf_enc)
MLK_EXTERNAL_API
uint64_t mlk_perf_enc();

#define mlk_perf_dec MLK_NAMESPACE_K(perf_dec)
MLK_EXTERNAL_API
uint64_t mlk_perf_dec();

#define mlk_perf_tempo_gen_matrix MLK_TEMPO_NAMESPACE_K(perf_gen_matrix)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_gen_matrix();

#define mlk_perf_tempo_keygen MLK_TEMPO_NAMESPACE_K(perf_keygen)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_keygen();

#define mlk_perf_tempo_encaps MLK_TEMPO_NAMESPACE_K(perf_encaps)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_encaps();

#endif
