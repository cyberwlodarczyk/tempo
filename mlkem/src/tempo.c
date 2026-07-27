#include "sys.h"
#if defined(MLK_SYS_X86_64_AVX2) || defined(MLK_SYS_X86_64_AVX512)
#include <immintrin.h>
#endif
#include "tempo.h"
#include "symmetric.h"
#include "poly_k.h"
#include "kem.h"

#define h_fls MLK_ADD_PARAM_SET(h_fls)
static void h_fls(
    mlk_polyvec *v,
    const uint8_t *seed,
    int transposed,
    int n)
{
    uint8_t buf[5 * SHAKE128_RATE];
    uint8_t ext_seed[MLKEM_SYMBYTES + 2];
    memcpy(ext_seed, seed, MLKEM_SYMBYTES);
    for (uint8_t y = 0; y < n; y++)
    {
        ext_seed[MLKEM_SYMBYTES + !transposed] = y;
        for (uint8_t x = 0; x < MLKEM_K; x++)
        {
#if defined(MLK_SYS_X86_64_AVX512)
            __attribute__((aligned(64))) int16_t poly[MLKEM_N];
#endif
            ext_seed[MLKEM_SYMBYTES + transposed] = x;
            mlk_xof_ctx ctx;
            mlk_xof_absorb(&ctx, ext_seed, sizeof(ext_seed));
            mlk_xof_squeezeblocks(buf, 5, &ctx);
            int ctr = 0;
            for (int i = 0, j = 0; i <= 279; i++, j += 3)
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
                    uint8_t *coeffs = (uint8_t *)poly;
                    for (int m = 0; m < 8; m++, coeffs += 64)
                    {
                        int mask = vec == m;
                        __m512i coeffs_avx = _mm512_load_si512(coeffs);
                        coeffs_avx = _mm512_mask_set1_epi16(
                            coeffs_avx,
                            lane & (__mmask32)-mask,
                            (int16_t)d_k);
                        _mm512_store_si512(coeffs, coeffs_avx);
                        flag += mask;
                    }
                    ctr += flag * d_ok;
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
                        flag += mask;
                    }
                    ctr += flag * d_ok;
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
#if defined(MLK_SYS_X86_64_AVX512)
            memcpy(&v[y].vec[x].coeffs, poly, sizeof(poly));
#endif
            mlk_xof_release(&ctx);
        }
    }
    mlk_zeroize(buf, sizeof(buf));
    mlk_zeroize(ext_seed, sizeof(ext_seed));
}

#define h_1 MLK_ADD_PARAM_SET(h_1)
static void h_1(
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
    h_fls(r, output, 0, 1);
    mlk_zeroize(input, inlen);
    mlk_zeroize(output, outlen);
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
    uint8_t *tag_a,
    uint8_t *tag_b,
    uint8_t *shared_secret,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *public_key,
    const uint8_t *apk,
    const uint8_t *ciphertext,
    const uint8_t *emphemeral_key)
{
    const size_t inlen = TEMPO_LEN_SID +
                         TEMPO_LEN_PWD +
                         MLKEM_INDCCA_LEN_PUBLIC_KEY +
                         TEMPO_LEN_APK +
                         MLKEM_INDCCA_LEN_CIPHERTEXT +
                         MLKEM_SSBYTES;
    const size_t outlen = 2 * TEMPO_LEN_TAG + TEMPO_LEN_SHARED_SECRET;
    uint8_t input[inlen];
    uint8_t output[outlen];
    size_t i = 0;
    memcpy(input, sid, TEMPO_LEN_SID);
    memcpy(input + (i += TEMPO_LEN_SID), pwd, TEMPO_LEN_PWD);
    memcpy(input + (i += TEMPO_LEN_PWD), public_key, MLKEM_INDCCA_LEN_PUBLIC_KEY);
    memcpy(input + (i += MLKEM_INDCCA_LEN_PUBLIC_KEY), apk, TEMPO_LEN_APK);
    memcpy(input + (i += TEMPO_LEN_APK), ciphertext, MLKEM_INDCCA_LEN_CIPHERTEXT);
    memcpy(input + (i += MLKEM_INDCCA_LEN_CIPHERTEXT), emphemeral_key, MLKEM_SSBYTES);
    mlk_shake256(output, outlen, input, inlen);
    memcpy(tag_a, output, TEMPO_LEN_TAG);
    memcpy(tag_b, output + TEMPO_LEN_TAG, TEMPO_LEN_TAG);
    memcpy(shared_secret, output + 2 * TEMPO_LEN_TAG, TEMPO_LEN_SHARED_SECRET);
    mlk_zeroize(input, inlen);
    mlk_zeroize(output, outlen);
}

MLK_INTERNAL_API
void mlk_tempo_gen_vector(
    mlk_polyvec *v,
    uint8_t seed[MLKEM_SYMBYTES],
    int transposed)
{
    h_fls(v, seed, transposed, 1);
}

MLK_INTERNAL_API
void mlk_tempo_gen_matrix(
    mlk_polymat *a,
    uint8_t seed[MLKEM_SYMBYTES],
    int transposed)
{
    h_fls(a->vec, seed, transposed, MLKEM_K);
}

MLK_EXTERNAL_API
int mlk_tempo_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    uint8_t *apk,
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
    ret = mlk_kem_keypair(public_key, secret_key);
    if (ret != 0)
    {
        goto cleanup;
    }
    memcpy(apk_seed, public_key + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);
    memcpy(poly, public_key, MLKEM_POLYVECBYTES);
    if (mlk_randombytes(r_seed, TEMPO_3LAMBDA) != 0)
    {
        ret = MLK_ERR_RNG_FAIL;
        goto cleanup;
    }
    h_1(&r, sid, pwd, apk_seed, r_seed);
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
    uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *ephemeral_key,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *apk)
{
    int ret = 0;
    const uint8_t *apk_u = apk;
    const uint8_t *apk_v = apk_u + TEMPO_3LAMBDA;
    const uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    mlk_polyvec r;
    mlk_polyvec v;
    uint8_t r_seed[TEMPO_3LAMBDA];
    uint8_t v_hash[TEMPO_3LAMBDA];
    uint8_t poly[MLKEM_POLYVECBYTES];
    h_2(v_hash, sid, pwd, apk_seed, apk_v);
    for (int i = 0; i < TEMPO_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk_u[i];
    }
    h_1(&r, sid, pwd, apk_seed, r_seed);
    mlk_polyvec_frombytes(&v, apk_v);
    mlk_polyvec_sub(&v, &r);
    mlk_polyvec_reduce(&v);
    mlk_polyvec_tobytes(poly, &v);
    memcpy(public_key + MLKEM_POLYVECBYTES, apk_seed, MLKEM_SYMBYTES);
    memcpy(public_key, poly, MLKEM_POLYVECBYTES);
    ret = mlk_kem_enc(ciphertext, ephemeral_key, public_key);
    mlk_zeroize(&r, sizeof(r));
    mlk_zeroize(&v, sizeof(v));
    mlk_zeroize(r_seed, TEMPO_3LAMBDA);
    mlk_zeroize(v_hash, TEMPO_3LAMBDA);
    mlk_zeroize(poly, MLKEM_POLYVECBYTES);
    return ret;
}

MLK_EXTERNAL_API
int mlk_tempo_decaps(
    uint8_t *ephemeral_key,
    const uint8_t *secret_key,
    const uint8_t *ciphertext)
{
    return mlk_kem_dec(ephemeral_key, ciphertext, secret_key);
}

MLK_EXTERNAL_API
void mlk_tempo_confirm(
    uint8_t *tag_a,
    uint8_t *tag_b,
    uint8_t *shared_secret,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *apk,
    const uint8_t *ciphertext,
    const uint8_t *public_key,
    const uint8_t *ephemeral_key)
{
    h_confirm(
        tag_a,
        tag_b,
        shared_secret,
        sid,
        pwd,
        public_key,
        apk,
        ciphertext,
        ephemeral_key);
}

MLK_EXTERNAL_API
int mlk_tempo_verify(const uint8_t *tag, const uint8_t *peer_tag)
{
    return mlk_ct_memcmp(tag, peer_tag, TEMPO_LEN_TAG);
}

#undef h_fls
#undef h_1
#undef h_2
#undef h_confirm
