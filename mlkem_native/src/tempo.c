#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "tempo.h"
#include "symmetric.h"
#include "kem.h"

#define h_fls MLK_ADD_PARAM_SET(h_fls) MLK_CONTEXT_PARAMETERS_2
static void h_fls(
    mlk_polyvec *a,
    const uint8_t *seed,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    mlk_xof_ctx ctx;
    MLK_ALLOC(buf, uint8_t, 5 * SHAKE128_RATE, context);
    MLK_ALLOC(ext_seed, uint8_t, MLKEM_SYMBYTES + 2, context);
    memcpy(ext_seed, seed, MLKEM_SYMBYTES);
    ext_seed[MLKEM_SYMBYTES + 1] = 0;
    for (uint8_t x = 0; x < MLKEM_K; x++)
    {
        ext_seed[MLKEM_SYMBYTES + 0] = x;
        mlk_xof_absorb(&ctx, ext_seed, sizeof(ext_seed));
        mlk_xof_squeezeblocks(buf, 5, &ctx);
        int ctr = 0;
        for (int i = 0, buf_i = 0; i <= 279; i++, buf_i += 3)
        {
            uint16_t d[2];
            int d_ok[2];
            d[0] = ((buf[buf_i + 0] >> 0) |
                    ((uint16_t)buf[buf_i + 1] << 8)) &
                   0xFFF;
            d[1] = ((buf[buf_i + 1] >> 4) |
                    ((uint16_t)buf[buf_i + 2] << 4)) &
                   0xFFF;
            d_ok[0] = (d[0] < MLKEM_Q);
            d_ok[1] = (d[1] < MLKEM_Q);
            for (int d_i = 0; d_i < 2; d_i++)
            {
                int flag = 0;
                for (int j = 0; j < MLKEM_N; j++)
                {
                    int match = (j == ctr);
                    int mask = match * d_ok[d_i];
                    int16_t *coeffs = a->vec[x].coeffs;
                    coeffs[j] = (int16_t)(coeffs[j] * (1 - mask) + d[d_i] * mask);
                    flag += mask;
                }
                ctr += flag;
            }
        }
    }
    mlk_xof_release(&ctx);
    MLK_FREE(buf, uint8_t, sizeof(buf), context);
    MLK_FREE(ext_seed, uint8_t, sizeof(ext_seed), context);
}

#define h_1 MLK_ADD_PARAM_SET(h_1) MLK_CONTEXT_PARAMETERS_5
static void h_1(
    mlk_polyvec *r,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *seed,
    const uint8_t *r_seed,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    const size_t inlen = MLKEM_TEMPO_SIDBYTES +
                         MLKEM_TEMPO_PWDBYTES +
                         MLKEM_SYMBYTES +
                         MLKEM_TEMPO_3LAMBDA;
    const size_t outlen = MLKEM_SYMBYTES;
    MLK_ALLOC(input, uint8_t, inlen, context);
    MLK_ALLOC(output, uint8_t, outlen, context);
    size_t i = 0;
    memcpy(input, sid, MLKEM_TEMPO_SIDBYTES);
    memcpy(input + (i += MLKEM_TEMPO_SIDBYTES), pwd, MLKEM_TEMPO_PWDBYTES);
    memcpy(input + (i += MLKEM_TEMPO_PWDBYTES), seed, MLKEM_SYMBYTES);
    memcpy(input + (i += MLKEM_SYMBYTES), r_seed, MLKEM_TEMPO_3LAMBDA);
    mlk_shake256(output, outlen, input, inlen);
    h_fls(r, output, context);
    MLK_FREE(input, uint8_t, inlen, context);
    MLK_FREE(output, uint8_t, outlen, context);
}

#define h_2 MLK_ADD_PARAM_SET(h_2) MLK_CONTEXT_PARAMETERS_5
static void h_2(
    uint8_t *v_hash,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *seed,
    const uint8_t *v_buf,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    const size_t inlen = MLKEM_TEMPO_SIDBYTES +
                         MLKEM_TEMPO_PWDBYTES +
                         MLKEM_SYMBYTES +
                         MLKEM_POLYVECBYTES;
    MLK_ALLOC(input, uint8_t, inlen, context);
    size_t i = 0;
    memcpy(input, sid, MLKEM_TEMPO_SIDBYTES);
    memcpy(input + (i += MLKEM_TEMPO_SIDBYTES), pwd, MLKEM_TEMPO_PWDBYTES);
    memcpy(input + (i += MLKEM_TEMPO_PWDBYTES), seed, MLKEM_SYMBYTES);
    memcpy(input + (i += MLKEM_SYMBYTES), v_buf, MLKEM_POLYVECBYTES);
    mlk_shake256(v_hash, MLKEM_TEMPO_3LAMBDA, input, inlen);
    MLK_FREE(input, uint8_t, inlen, context);
}

#define h_confirm MLK_ADD_PARAM_SET(h_confirm) MLK_CONTEXT_PARAMETERS_9
static inline void h_confirm(
    uint8_t *tag_a,
    uint8_t *tag_b,
    uint8_t *shared_secret,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *public_key,
    const uint8_t *apk,
    const uint8_t *ciphertext,
    const uint8_t *emphemeral_key,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    const size_t inlen = MLKEM_TEMPO_SIDBYTES +
                         MLKEM_TEMPO_PWDBYTES +
                         MLKEM_INDCCA_PUBLICKEYBYTES +
                         MLKEM_TEMPO_APKBYTES +
                         MLKEM_INDCCA_CIPHERTEXTBYTES +
                         MLKEM_SSBYTES;
    const size_t outlen = 2 * MLKEM_TEMPO_TAGBYTES + MLKEM_TEMPO_SSBYTES;
    MLK_ALLOC(input, uint8_t, inlen, context);
    MLK_ALLOC(output, uint8_t, outlen, context);
    size_t i = 0;
    memcpy(input, sid, MLKEM_TEMPO_SIDBYTES);
    memcpy(input + (i += MLKEM_TEMPO_SIDBYTES), pwd, MLKEM_TEMPO_PWDBYTES);
    memcpy(input + (i += MLKEM_TEMPO_PWDBYTES), public_key, MLKEM_INDCCA_PUBLICKEYBYTES);
    memcpy(input + (i += MLKEM_INDCCA_PUBLICKEYBYTES), apk, MLKEM_TEMPO_APKBYTES);
    memcpy(input + (i += MLKEM_TEMPO_APKBYTES), ciphertext, MLKEM_INDCCA_CIPHERTEXTBYTES);
    memcpy(input + (i += MLKEM_INDCCA_CIPHERTEXTBYTES), emphemeral_key, MLKEM_SSBYTES);
    mlk_shake256(output, outlen, input, inlen);
    memcpy(tag_a, output, MLKEM_TEMPO_TAGBYTES);
    memcpy(tag_b, output + MLKEM_TEMPO_TAGBYTES, MLKEM_TEMPO_TAGBYTES);
    memcpy(shared_secret, output + 2 * MLKEM_TEMPO_TAGBYTES, MLKEM_TEMPO_SSBYTES);
    MLK_FREE(input, uint8_t, inlen, context);
    MLK_FREE(output, uint8_t, outlen, context);
}

MLK_EXTERNAL_API
void mlk_tempo_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    uint8_t *apk,
    const uint8_t *sid,
    const uint8_t *pwd,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    mlk_kem_keypair(public_key, secret_key, context);
    MLK_ALLOC(poly, uint8_t, MLKEM_POLYVECBYTES, context);
    uint8_t *apk_u = apk;
    uint8_t *apk_v = apk_u + MLKEM_TEMPO_3LAMBDA;
    uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    memcpy(apk_seed, public_key + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);
    memcpy(poly, public_key, MLKEM_POLYVECBYTES);
    MLK_ALLOC(r_seed, uint8_t, MLKEM_TEMPO_3LAMBDA, context);
    RAND_bytes(r_seed, MLKEM_TEMPO_3LAMBDA);
    mlk_polyvec r;
    h_1(&r, sid, pwd, apk_seed, r_seed, context);
    mlk_polyvec t;
    mlk_polyvec_frombytes(&t, poly);
    mlk_polyvec_add(&t, &r);
    mlk_polyvec_reduce(&t);
    mlk_polyvec_tobytes(apk + MLKEM_TEMPO_3LAMBDA, &t);
    MLK_ALLOC(v_hash, uint8_t, MLKEM_TEMPO_3LAMBDA, context);
    h_2(v_hash, sid, pwd, apk_seed, apk_v, context);
    for (int i = 0; i < MLKEM_TEMPO_3LAMBDA; i++)
    {
        apk_u[i] = v_hash[i] ^ r_seed[i];
    }
    mlk_zeroize(&r, sizeof(r));
    mlk_zeroize(&t, sizeof(t));
    MLK_FREE(poly, uint8_t, sizeof(poly), context);
    MLK_FREE(r_seed, uint8_t, sizeof(r_seed), context);
    MLK_FREE(v_hash, uint8_t, sizeof(v_hash), context);
}

MLK_EXTERNAL_API
void mlk_tempo_encaps(
    uint8_t *public_key,
    uint8_t *ciphertext,
    uint8_t *ephemeral_key,
    const uint8_t *sid,
    const uint8_t *pwd,
    const uint8_t *apk,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    MLK_ALLOC(v_hash, uint8_t, MLKEM_TEMPO_3LAMBDA, context);
    const uint8_t *apk_u = apk;
    const uint8_t *apk_v = apk_u + MLKEM_TEMPO_3LAMBDA;
    const uint8_t *apk_seed = apk_v + MLKEM_POLYVECBYTES;
    h_2(v_hash, sid, pwd, apk_seed, apk_v, context);
    MLK_ALLOC(r_seed, uint8_t, MLKEM_TEMPO_3LAMBDA, context);
    for (int i = 0; i < MLKEM_TEMPO_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk_u[i];
    }
    mlk_polyvec r;
    h_1(&r, sid, pwd, apk_seed, r_seed, context);
    mlk_polyvec v;
    mlk_polyvec_frombytes(&v, apk_v);
    mlk_polyvec_sub(&v, &r);
    mlk_polyvec_reduce(&v);
    MLK_ALLOC(poly, uint8_t, MLKEM_POLYVECBYTES, context);
    mlk_polyvec_tobytes(poly, &v);
    memcpy(public_key + MLKEM_POLYVECBYTES, apk_seed, MLKEM_SYMBYTES);
    memcpy(public_key, poly, MLKEM_POLYVECBYTES);
    mlk_kem_enc(ciphertext, ephemeral_key, public_key, context);
    mlk_zeroize(&r, sizeof(r));
    mlk_zeroize(&v, sizeof(v));
    MLK_FREE(r_seed, uint8_t, MLKEM_TEMPO_3LAMBDA, context);
    MLK_FREE(v_hash, uint8_t, MLKEM_TEMPO_3LAMBDA, context);
    MLK_FREE(poly, uint8_t, MLKEM_POLYVECBYTES, context);
}

MLK_EXTERNAL_API
void mlk_tempo_decaps(
    uint8_t *ephemeral_key,
    const uint8_t *secret_key,
    const uint8_t *ciphertext,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    mlk_kem_dec(ephemeral_key, ciphertext, secret_key, context);
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
    const uint8_t *ephemeral_key,
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
    h_confirm(
        tag_a,
        tag_b,
        shared_secret,
        sid,
        pwd,
        apk,
        ciphertext,
        public_key,
        ephemeral_key,
        context);
}

MLK_EXTERNAL_API
int mlk_tempo_verify(const uint8_t *tag, const uint8_t *peer_tag)
{
    return CRYPTO_memcmp(tag, peer_tag, MLKEM_TEMPO_TAGBYTES);
}
