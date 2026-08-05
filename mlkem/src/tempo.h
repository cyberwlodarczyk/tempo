#ifndef MLK_TEMPO_H
#define MLK_TEMPO_H

#include "common.h"
#include "poly_k.h"

#if defined(MLK_CONFIG_TEST) || defined(MLK_CONFIG_PERF)
#ifdef MLK_CONFIG_TEMPO_FLS185
#define MLK_TEMPO_FLS_RETURN int
#else
#define MLK_TEMPO_FLS_RETURN void
#endif

#define mlk_tempo_gen_vector MLK_TEMPO_NAMESPACE_K(gen_vector)
MLK_INTERNAL_API
MLK_TEMPO_FLS_RETURN mlk_tempo_gen_vector(
    mlk_polyvec *a,
    uint8_t seed[MLKEM_SYMBYTES],
    int transposed);

#define mlk_tempo_gen_matrix MLK_TEMPO_NAMESPACE_K(gen_matrix)
MLK_INTERNAL_API
MLK_TEMPO_FLS_RETURN mlk_tempo_gen_matrix(
    mlk_polymat *a,
    uint8_t seed[MLKEM_SYMBYTES],
    int transposed);
#endif

#define mlk_tempo_keygen MLK_TEMPO_NAMESPACE_K(keygen)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_tempo_keygen(
    uint8_t *pk,
    uint8_t *apk,
    uint8_t *sk,
    const uint8_t *sid,
    const uint8_t *pwd);

#define mlk_tempo_encaps MLK_TEMPO_NAMESPACE_K(encaps)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_tempo_encaps(
    uint8_t *ss,
    uint8_t *ct,
    uint8_t *tag,
    const uint8_t *apk,
    const uint8_t *sid,
    const uint8_t *pwd);

#define mlk_tempo_decaps MLK_TEMPO_NAMESPACE_K(decaps)
MLK_EXTERNAL_API
MLK_MUST_CHECK_RETURN_VALUE
int mlk_tempo_decaps(
    uint8_t *ss,
    const uint8_t *pk,
    const uint8_t *apk,
    const uint8_t *sk,
    const uint8_t *ct,
    const uint8_t *tag,
    const uint8_t *sid,
    const uint8_t *pwd);

#endif
