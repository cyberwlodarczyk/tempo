#include "sys.h"
#if defined(MLK_SYS_X86_64_AVX2) || defined(MLK_SYS_X86_64_AVX512)
#include <immintrin.h>
#endif
#include "tempo.h"
#include "symmetric.h"
#include "poly_k.h"
#include "indcpa.h"
#include "kem.h"

#ifdef MLK_CONFIG_TEMPO_FLS185
#define FLS_ITER 185
#define FLS_XOF_BLOCKS 4
#define FLS_RETURN int
#else
#define FLS_ITER 280
#define FLS_XOF_BLOCKS 5
#define FLS_RETURN void
#endif

#define h_fls MLK_ADD_PARAM_SET(h_fls)
static FLS_RETURN h_fls(
    mlk_polyvec *v,
    const uint8_t *seed,
    int transposed,
    int n)
{
    uint8_t buf[FLS_XOF_BLOCKS * SHAKE128_RATE];
    uint8_t ext_seed[MLKEM_SYMBYTES + 2];
    memcpy(ext_seed, seed, MLKEM_SYMBYTES);
#ifdef MLK_CONFIG_TEMPO_FLS185
    int ret = 1;
#endif
    for (uint8_t y = 0; y < n; y++)
    {
        ext_seed[MLKEM_SYMBYTES + !transposed] = y;
        for (uint8_t x = 0; x < MLKEM_K; x++)
        {
            ext_seed[MLKEM_SYMBYTES + transposed] = x;
            mlk_xof_ctx ctx;
            mlk_xof_absorb(&ctx, ext_seed, sizeof(ext_seed));
            mlk_xof_squeezeblocks(buf, FLS_XOF_BLOCKS, &ctx);
            int ctr = 0;
            for (int i = 0, j = 0; i < FLS_ITER; i++, j += 3)
            {
                uint16_t d[2];
                d[0] = ((buf[j + 0] >> 0) |
                        ((uint16_t)buf[j + 1] << 8)) &
                       0xFFF;
                d[1] = ((buf[j + 1] >> 4) |
                        ((uint16_t)buf[j + 2] << 4)) &
                       0xFFF;
                for (int k = 0; k < 2; k++)
                {
                    int d_ok = d[k] < MLKEM_Q;
#if defined(MLK_SYS_X86_64_AVX512)
                    int d_k = d[k] * d_ok;
                    int flag = 0;
                    int vec = ctr >> 5;
                    __mmask32 lane = 1 << (ctr & 31);
                    uint8_t *coeffs = (uint8_t *)v[y].vec[x].coeffs;
                    for (int m = 0; m < 8; m++, coeffs += 64)
                    {
                        int mask = vec == m;
                        __m512i coeffs_avx = _mm512_load_si512(coeffs);
                        coeffs_avx = _mm512_mask_set1_epi16(
                            coeffs_avx,
                            lane & (__mmask32)-mask,
                            (int16_t)d_k);
                        _mm512_store_si512(coeffs, coeffs_avx);
                        flag |= mask;
                    }
                    ctr += flag & d_ok;
#elif defined(MLK_SYS_X86_64_AVX2)
                    __m256i lane_avx = _mm256_cmpeq_epi16(
                        _mm256_setr_epi16(
                            0, 1, 2, 3, 4, 5, 6, 7,
                            8, 9, 10, 11, 12, 13, 14, 15),
                        _mm256_set1_epi16(ctr & 15));
                    __m256i d_avx = _mm256_set1_epi16((int16_t)(d[k] * d_ok));
                    d_avx = _mm256_and_si256(d_avx, lane_avx);
                    uint8_t *coeffs = (uint8_t *)v[y].vec[x].coeffs;
                    int flag = 0;
                    for (int m = 0; m < 16; m++, coeffs += 32)
                    {
                        int mask = (ctr >> 4) == m;
                        __m256i mask_avx = _mm256_set1_epi16((int16_t)-(mask));
                        __m256i d_mask_avx = _mm256_and_si256(d_avx, mask_avx);
                        __m256i coeffs_avx = _mm256_load_si256((const __m256i *)coeffs);
                        mask_avx = _mm256_and_si256(mask_avx, lane_avx);
                        coeffs_avx = _mm256_andnot_si256(mask_avx, coeffs_avx);
                        coeffs_avx = _mm256_or_si256(coeffs_avx, d_mask_avx);
                        _mm256_store_si256((__m256i *)coeffs, coeffs_avx);
                        flag |= mask;
                    }
                    ctr += flag & d_ok;
#else
                    int flag = 0;
                    for (int m = 0; m < MLKEM_N; m++)
                    {
                        int match = (m == ctr);
                        int mask = match * d_ok;
                        int16_t *coeffs = v[y].vec[x].coeffs;
                        coeffs[m] = (int16_t)(coeffs[m] * (1 - mask) + d[k] * mask);
                        flag += mask;
                    }
                    ctr += flag;
#endif
                }
            }
#ifdef MLK_CONFIG_TEMPO_FLS185
            ret &= ctr == 256;
#endif
            mlk_xof_release(&ctx);
        }
    }
    mlk_zeroize(buf, sizeof(buf));
    mlk_zeroize(ext_seed, sizeof(ext_seed));
#ifdef MLK_CONFIG_TEMPO_FLS185
    return ret;
#endif
}

#define h_1 MLK_ADD_PARAM_SET(h_1)
static FLS_RETURN h_1(
    mlk_polyvec *r,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *seed,
    const uint8_t *r_seed)
{
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_SYMBYTES +
                         TEMPO_3LAMBDA;
    const size_t outlen = MLKEM_SYMBYTES;
    uint8_t input[inlen];
    uint8_t output[outlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), seed, MLKEM_SYMBYTES);
    memcpy(input + (i += MLKEM_SYMBYTES), r_seed, TEMPO_3LAMBDA);
    mlk_shake256(output, outlen, input, inlen);
#ifdef MLK_CONFIG_TEMPO_FLS185
    int ret = h_fls(r, output, 0, 1);
#else
    h_fls(r, output, 0, 1);
#endif
    mlk_zeroize(input, inlen);
    mlk_zeroize(output, outlen);
#ifdef MLK_CONFIG_TEMPO_FLS185
    return ret;
#endif
}

#define h_2 MLK_ADD_PARAM_SET(h_2)
static void h_2(
    uint8_t *v_hash,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *seed,
    const uint8_t *v_buf)
{
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_SYMBYTES +
                         MLKEM_POLYVECBYTES;
    uint8_t input[inlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), seed, MLKEM_SYMBYTES);
    memcpy(input + (i += MLKEM_SYMBYTES), v_buf, MLKEM_POLYVECBYTES);
    mlk_shake256(v_hash, TEMPO_3LAMBDA, input, inlen);
    mlk_zeroize(input, inlen);
}

#define h_confirm MLK_ADD_PARAM_SET(h_confirm)
static inline void h_confirm(
    uint8_t *tag,
    uint8_t *shared_secret,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *public_key,
    const uint8_t *apk,
    const uint8_t *ciphertext,
    const uint8_t *key)
{
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_INDCCA_LEN_PUBLIC_KEY +
                         TEMPO_LEN_APK +
                         MLKEM_INDCCA_LEN_CIPHERTEXT +
                         MLKEM_SSBYTES;
    const size_t outlen = TEMPO_LEN_TAG + TEMPO_LEN_SHARED_SECRET;
    uint8_t input[inlen];
    uint8_t output[outlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), public_key, MLKEM_INDCCA_LEN_PUBLIC_KEY);
    memcpy(input + (i += MLKEM_INDCCA_LEN_PUBLIC_KEY), apk, TEMPO_LEN_APK);
    memcpy(input + (i += TEMPO_LEN_APK), ciphertext, MLKEM_INDCCA_LEN_CIPHERTEXT);
    memcpy(input + (i += MLKEM_INDCCA_LEN_CIPHERTEXT), key, MLKEM_SSBYTES);
    mlk_shake256(output, outlen, input, inlen);
    memcpy(tag, output, TEMPO_LEN_TAG);
    memcpy(shared_secret, output + TEMPO_LEN_TAG, TEMPO_LEN_SHARED_SECRET);
    mlk_zeroize(input, inlen);
    mlk_zeroize(output, outlen);
}

#if defined(MLK_CONFIG_TEST) || defined(MLK_CONFIG_PERF)
MLK_INTERNAL_API
FLS_RETURN mlk_tempo_gen_vector(
    mlk_polyvec *v,
    uint8_t seed[MLKEM_SYMBYTES],
    int transposed)
{
#ifdef MLK_CONFIG_TEMPO_FLS185
    return h_fls(v, seed, transposed, 1);
#else
    h_fls(v, seed, transposed, 1);
#endif
}

MLK_INTERNAL_API
FLS_RETURN mlk_tempo_gen_matrix(
    mlk_polymat *a,
    uint8_t seed[MLKEM_SYMBYTES],
    int transposed)
{
#ifdef MLK_CONFIG_TEMPO_FLS185
    return h_fls(a->vec, seed, transposed, MLKEM_K);
#else
    h_fls(a->vec, seed, transposed, MLKEM_K);
#endif
}
#endif

MLK_EXTERNAL_API
int mlk_tempo_keygen(
    uint8_t *pk,
    uint8_t *apk,
    uint8_t *sk,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    int ret = 0;
    uint8_t *apk_u = apk;
    uint8_t *apk_v = apk_u + TEMPO_3LAMBDA;
    uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    mlk_polyvec r;
    mlk_polyvec t;
    uint8_t poly[MLKEM_POLYVECBYTES];
    uint8_t r_seed[TEMPO_3LAMBDA];
    uint8_t v_hash[TEMPO_3LAMBDA];
    ret = mlk_kem_keypair(pk, sk);
    if (ret != 0)
    {
        goto cleanup;
    }
    memcpy(apk_seed, pk + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);
    memcpy(poly, pk, MLKEM_POLYVECBYTES);
#ifdef MLK_CONFIG_TEMPO_FLS185
    int fls_ret = 0;
#else
    int fls_ret = 1;
#endif
    do
    {
        if (mlk_randombytes(r_seed, TEMPO_3LAMBDA) != 0)
        {
            ret = MLK_ERR_RNG_FAIL;
            goto cleanup;
        }
#ifdef MLK_CONFIG_TEMPO_FLS185
        fls_ret = h_1(&r, sid, pwd, apk_seed, r_seed);
#else
        h_1(&r, sid, pwd, apk_seed, r_seed);
#endif
    } while (fls_ret != 1);
    mlk_polyvec_frombytes(&t, poly);
    mlk_polyvec_add(&t, &r);
    mlk_polyvec_reduce(&t);
    mlk_polyvec_tobytes(apk + TEMPO_3LAMBDA, &t);
    h_2(v_hash, sid, pwd, apk_seed, apk_v);
    for (int i = 0; i < TEMPO_3LAMBDA; i++)
    {
        apk_u[i] = v_hash[i] ^ r_seed[i];
    }
cleanup:
    mlk_zeroize(&r, sizeof(r));
    mlk_zeroize(&t, sizeof(t));
    mlk_zeroize(poly, sizeof(poly));
    mlk_zeroize(r_seed, sizeof(r_seed));
    mlk_zeroize(v_hash, sizeof(v_hash));
    return ret;
}

MLK_EXTERNAL_API
int mlk_tempo_encaps(
    uint8_t *ss,
    uint8_t *ct,
    uint8_t *tag,
    const uint8_t *apk,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    int ret = 0;
    const uint8_t *apk_u = apk;
    const uint8_t *apk_v = apk_u + TEMPO_3LAMBDA;
    const uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    mlk_polyvec r;
#ifdef MLK_CONFIG_TEMPO_FLS185
    mlk_polyvec rx;
#endif
    mlk_polyvec v;
    uint8_t r_seed[TEMPO_3LAMBDA];
    uint8_t v_hash[TEMPO_3LAMBDA];
    uint8_t pk[MLKEM_INDCCA_LEN_PUBLIC_KEY];
    uint8_t key[MLKEM_SSBYTES];
    ret = mlk_kem_check_pk(apk_v);
    if (ret != 0)
    {
        goto cleanup;
    }
    h_2(v_hash, sid, pwd, apk_seed, apk_v);
    for (int i = 0; i < TEMPO_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk_u[i];
    }
    mlk_polyvec_frombytes(&v, apk_v);
#ifdef MLK_CONFIG_TEMPO_FLS185
    int fls_ret = h_1(&r, sid, pwd, apk_seed, r_seed);
    uint8_t rx_seed[MLKEM_SYMBYTES];
    if (mlk_randombytes(rx_seed, MLKEM_SYMBYTES) != 0)
    {
        ret = MLK_ERR_RNG_FAIL;
        goto cleanup;
    }
    mlk_gen_vector(&rx, rx_seed, 0);
    mlk_polyvec_sub_mask(&v, &rx, &r, fls_ret);
#else
    h_1(&r, sid, pwd, apk_seed, r_seed);
    mlk_polyvec_sub(&v, &r);
#endif
    mlk_polyvec_reduce(&v);
    mlk_polyvec_tobytes(pk, &v);
    memcpy(pk + MLKEM_POLYVECBYTES, apk_seed, MLKEM_SYMBYTES);
    ret = mlk_kem_enc_valid_pk(ct, key, pk);
    if (ret != 0)
    {
        goto cleanup;
    }
    h_confirm(tag, ss, sid, pwd, pk, apk, ct, key);
cleanup:
    mlk_zeroize(&r, sizeof(r));
#ifdef MLK_CONFIG_TEMPO_FLS185
    mlk_zeroize(&rx, sizeof(rx));
#endif
    mlk_zeroize(&v, sizeof(v));
    mlk_zeroize(r_seed, TEMPO_3LAMBDA);
    mlk_zeroize(v_hash, TEMPO_3LAMBDA);
    mlk_zeroize(pk, MLKEM_INDCCA_LEN_PUBLIC_KEY);
    mlk_zeroize(key, MLKEM_SSBYTES);
    return ret;
}

MLK_EXTERNAL_API
int mlk_tempo_decaps(
    uint8_t *ss,
    const uint8_t *pk,
    const uint8_t *apk,
    const uint8_t *sk,
    const uint8_t *ct,
    const uint8_t *tag,
    const uint8_t *sid,
    const uint8_t *pwd)
{
    int ret = 0;
    uint8_t key[MLKEM_SSBYTES];
    uint8_t tag2[TEMPO_LEN_TAG];
    uint8_t ss1[TEMPO_LEN_SHARED_SECRET];
    uint8_t ss2[TEMPO_LEN_SHARED_SECRET];
    ret = mlk_kem_dec(key, ct, sk);
    if (ret != 0)
    {
        goto cleanup;
    }
    h_confirm(tag2, ss1, sid, pwd, pk, apk, ct, key);
    if (mlk_randombytes(ss2, TEMPO_LEN_SHARED_SECRET) != 0)
    {
        ret = MLK_ERR_RNG_FAIL;
        goto cleanup;
    }
    uint8_t ok = mlk_ct_memcmp(tag, tag2, TEMPO_LEN_TAG) == 0;
    mlk_ct_cmov_zero(ss, ss1, TEMPO_LEN_SHARED_SECRET, !ok);
    mlk_ct_cmov_zero(ss, ss2, TEMPO_LEN_SHARED_SECRET, ok);
cleanup:
    mlk_zeroize(key, MLKEM_SSBYTES);
    mlk_zeroize(tag2, TEMPO_LEN_TAG);
    mlk_zeroize(ss1, TEMPO_LEN_SHARED_SECRET);
    mlk_zeroize(ss2, TEMPO_LEN_SHARED_SECRET);
    return ret;
}

#undef h_fls
#undef h_1
#undef h_2
#undef h_confirm
