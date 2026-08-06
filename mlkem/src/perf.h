#ifndef MLK_PERF_H
#define MLK_PERF_H

#include "common.h"

#ifdef MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define mlk_perf_rand_32_bytes MLK_NAMESPACE(perf_rand_32_bytes)
MLK_EXTERNAL_API
uint64_t mlk_perf_rand_32_bytes(void);
#endif

#define mlk_perf_gen_vector MLK_NAMESPACE_K(perf_gen_vector)
MLK_EXTERNAL_API
uint64_t mlk_perf_gen_vector(void);

#define mlk_perf_gen_matrix MLK_NAMESPACE_K(perf_gen_matrix)
MLK_EXTERNAL_API
uint64_t mlk_perf_gen_matrix(void);

#define mlk_perf_keypair MLK_NAMESPACE_K(perf_keypair)
MLK_EXTERNAL_API
uint64_t mlk_perf_keypair(void);

#define mlk_perf_enc MLK_NAMESPACE_K(perf_enc)
MLK_EXTERNAL_API
uint64_t mlk_perf_enc(void);

#define mlk_perf_dec MLK_NAMESPACE_K(perf_dec)
MLK_EXTERNAL_API
uint64_t mlk_perf_dec(void);

#define mlk_perf_tempo_gen_vector MLK_TEMPO_NAMESPACE_K(perf_gen_vector)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_gen_vector(void);

#define mlk_perf_tempo_gen_matrix MLK_TEMPO_NAMESPACE_K(perf_gen_matrix)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_gen_matrix(void);

#define mlk_perf_tempo_keygen MLK_TEMPO_NAMESPACE_K(perf_keygen)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_keygen(void);

#define mlk_perf_tempo_encaps MLK_TEMPO_NAMESPACE_K(perf_encaps)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_encaps(void);

#define mlk_perf_tempo_decaps MLK_TEMPO_NAMESPACE_K(perf_decaps)
MLK_EXTERNAL_API
uint64_t mlk_perf_tempo_decaps(void);

#endif
