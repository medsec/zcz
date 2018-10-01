/*
// @author anonymized
// @last-modified 2018-08
// Copyright 2018 anonymized
// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
*/

#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gfmul.h"
#include "utils-opt.h"
#include "deoxysbc.h"
#include "zcz.h"

// ---------------------------------------------------------------------
// Length functions
// ---------------------------------------------------------------------

static int is_too_short(const size_t num_bytes) {
    return num_bytes < ZCZ_MIN_NUM_MESSAGE_BYTES;
}

// ---------------------------------------------------------------------

static int is_length_ok_for_zcz(const size_t num_bytes) {
    return !is_too_short(num_bytes);
}

// ---------------------------------------------------------------------

static size_t get_num_full_di_blocks(const size_t num_bytes) {
    return (size_t)(num_bytes / ZCZ_NUM_BYTES_IN_DI_BLOCK);
}

// ---------------------------------------------------------------------

static int is_length_ok_for_zcz_basic(const size_t num_bytes) {
    return (!is_too_short(num_bytes))
        && (num_bytes <= ZCZ_BASIC_MAX_NUM_MESSAGE_BYTES)
        && ((num_bytes % ZCZ_NUM_BYTES_IN_DI_BLOCK) == 0);
}

// ---------------------------------------------------------------------

static size_t get_num_chunks(const size_t num_di_blocks) {
    return (size_t)((num_di_blocks + ZCZ_NUM_DI_BLOCKS_IN_CHUNK - 1)
        / (ZCZ_NUM_DI_BLOCKS_IN_CHUNK));
}

// ---------------------------------------------------------------------
// Scheme functions
// ---------------------------------------------------------------------

static inline void vxor_di_block(uint8_t in_out[ZCZ_NUM_BYTES_IN_DI_BLOCK],
                                 const uint8_t b[ZCZ_NUM_BYTES_IN_DI_BLOCK]) {
    const __m256i x = avx_loadu(in_out);
    const __m256i y = avx_loadu(b);
    avx_storeu(in_out, avx_xor(x, y));
}

// ---------------------------------------------------------------------

static void pad_message(uint8_t* target,
                        const size_t num_source_bytes,
                        const size_t num_target_bytes) {
    if (num_target_bytes <= num_source_bytes) {
        puts("[FATAL] Cannot pad message");
        return;
    }

    // Set the first byte to 100...0 and the remaining bytes
    // to all zeroes.

    target[num_source_bytes] = 0x80;
    const size_t num_zero_bytes = num_target_bytes - num_source_bytes - 1;
    memset(target + num_source_bytes + 1, 0x00, num_zero_bytes);
}

// ---------------------------------------------------------------------

static void hash(zcz_ctx_t* ctx,
                 const uint8_t* input,
                 uint8_t* output,
                 const size_t domain) {
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    __m128i u = loadu(input);
    __m128i v = loadu((input + ZCZ_NUM_BYTES_IN_BLOCK));

    __m128i u_prime;
    __m128i v_prime;

    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_PARTIAL,
                              domain,
                              v,
                              u,
                              &u_prime);

    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_PARTIAL,
                              domain + 1,
                              v,
                              u,
                              &v_prime);

    storeu(output, u_prime);
    storeu((output + ZCZ_NUM_BYTES_IN_BLOCK), v_prime);
}

// ---------------------------------------------------------------------

#define load_eight_blocks(states, source) do {\
    states[0] = load(source); \
    states[1] = load((source + 2)); \
    states[2] = load((source + 4)); \
    states[3] = load((source + 6)); \
    states[4] = load((source + 8)); \
    states[5] = load((source + 10)); \
    states[6] = load((source + 12)); \
    states[7] = load((source + 14)); \
} while (0)

// ---------------------------------------------------------------------

#define store_eight_blocks(target, states) do {\
    store(target, states[0]); \
    store((target + 2), states[1]); \
    store((target + 4), states[2]); \
    store((target + 6), states[3]); \
    store((target + 8), states[4]); \
    store((target + 10), states[5]); \
    store((target + 12), states[6]); \
    store((target + 14), states[7]); \
} while (0)

// ---------------------------------------------------------------------

#define vxor_eight(x, y, z) do {\
    z[0] = vxor(x[0], y[0]);\
    z[1] = vxor(x[1], y[1]);\
    z[2] = vxor(x[2], y[2]);\
    z[3] = vxor(x[3], y[3]);\
    z[4] = vxor(x[4], y[4]);\
    z[5] = vxor(x[5], y[5]);\
    z[6] = vxor(x[6], y[6]);\
    z[7] = vxor(x[7], y[7]);\
} while (0)

// ---------------------------------------------------------------------

#define vxor_eight_same_x(x, y, z) do {\
    z[0] = vxor(x, y[0]);\
    z[1] = vxor(x, y[1]);\
    z[2] = vxor(x, y[2]);\
    z[3] = vxor(x, y[3]);\
    z[4] = vxor(x, y[4]);\
    z[5] = vxor(x, y[5]);\
    z[6] = vxor(x, y[6]);\
    z[7] = vxor(x, y[7]);\
} while (0)

// ---------------------------------------------------------------------

#define set_eight_blocks_same_x(x, y) do {\
    y[0] = x; \
    y[1] = x; \
    y[2] = x; \
    y[3] = x; \
    y[4] = x; \
    y[5] = x; \
    y[6] = x; \
    y[7] = x; \
} while (0)

// ---------------------------------------------------------------------

static void encrypt_until(zcz_ctx_t* ctx,
                          uint8_t* target,
                          const uint8_t* source,
                          const size_t num_di_blocks) {
    __m128i states[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i tweaks[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i* source_position = (__m128i*)source;
    __m128i* target_position = (__m128i*)target;

    size_t num_di_blocks_remaining = num_di_blocks;
    size_t tweak_counter = 0;
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    // Zeroize the hash values X_L and X_R at the beginning
    __m128i x_l = vzero;
    __m128i x_r = vzero;
    __m128i tmp;

    deoxys_bc_128_384_setup_base_counters(cipher_ctx,
                                          ZCZ_DOMAIN_TOP,
                                          tweak_counter);

    tweak_counter = 1;

    // ---------------------------------------------------------------------
    // Next 8 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE) {
        load_eight_blocks(states, source_position);        // L_1 .. L_8
        load_eight_blocks(tweaks, (source_position + 1));  // R_1 .. R_8

        // Obtain the values X_i in states
        deoxys_bc_128_384_encrypt_eight_eight(cipher_ctx,
                                              tweak_counter,
                                              tweaks,
                                              states);

        // Copy the values X_i to the buffer
        store_eight_blocks(target_position, states);        // Copy the X_i's
        store_eight_blocks((target_position + 1), tweaks);  // Copy the R_i's

        // Update X_L = X_L * 2^8 xor X_1 * 2^7 xor ... X_7 * 2 xor X_8
        x_l = gf_2_128_double_eight(x_l, states);

        // states[i] = X_i xor R_i
        // Update X_R = X_R * (4)^8 xor X_1 * 4^7 xor ... X_7 * 4 xor X_8
        vxor_eight(states, tweaks, states);

        x_r = gf_2_128_times_four_eight(x_r, states);

        num_di_blocks_remaining -= ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // We used 8
        target_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        source_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        tweak_counter += ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // Tweak += 8
    }

    // ---------------------------------------------------------------------
    // Tail: 0..7 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > 1) {
        states[0] = load(source_position);
        tweaks[0] = load((source_position + 1));

        deoxys_bc_128_384_encrypt(cipher_ctx,
                                  ZCZ_DOMAIN_TOP,
                                  tweak_counter,
                                  tweaks[0],
                                  states[0],
                                  states);

        // Copy X_i || R_i to the buffer
        store(target_position, states[0]);
        store((target_position + 1), tweaks[0]);

        // Update X_L
        gf_2_128_double(x_l, x_l, tmp);
        x_l = vxor(x_l, states[0]);

        // Update X_R
        gf_2_128_times_four(x_r, x_r, tmp);

        x_r = vxor3(x_r, states[0], tweaks[0]);

        num_di_blocks_remaining -= 1;  // We used 32 bytes
        target_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        source_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        tweak_counter += 1;
    }

    // ---------------------------------------------------------------------
    // Process X_L and X_R.
    // Note: This destroys the previous round tweaks
    // ---------------------------------------------------------------------

    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_XL,
                              num_di_blocks,
                              x_r,
                              x_l,
                              &(ctx->x_l));
    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_XR,
                              num_di_blocks,
                              x_l,
                              x_r,
                              &(ctx->x_r));
}

// ---------------------------------------------------------------------
// Encryption component functions
// ---------------------------------------------------------------------

static void encrypt_top_layer(zcz_ctx_t* ctx,
                              uint8_t* state,
                              const uint8_t* plaintext,
                              const size_t num_di_blocks) {
    deoxys_bc_128_384_setup_base_counters(&(ctx->cipher_ctx),
                                          ZCZ_DOMAIN_TOP,
                                          0);
    encrypt_until(ctx, state, plaintext, num_di_blocks);
}

// ---------------------------------------------------------------------

static void encrypt_middle_layer(zcz_ctx_t* ctx,
                                 uint8_t* state,
                                 const size_t num_di_blocks) {
    __m128i tweak;
    __m128i* source_position = (__m128i*)state;
    __m128i* target_position = (__m128i*)state;

    size_t num_di_blocks_without_final = num_di_blocks;

    if (num_di_blocks > 0) {
        num_di_blocks_without_final--;
    }

    const size_t num_chunks = get_num_chunks(num_di_blocks_without_final);
    size_t k = 1;
    size_t tweak_counter = 0;
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    // ---------------------------------------------------------------------
    // Zeroize the hash values Y_L and Y_R at the beginning
    // ---------------------------------------------------------------------

    __m128i s_i;
    __m128i l_i;
    __m128i r_i;

    __m128i x_i[8];
    __m128i y_i[8];
    __m128i z_i_j[8];

    __m128i y_l = vzero;
    __m128i y_r = vzero;
    __m128i tmp;

    // ---------------------------------------------------------------------
    // Init domain and base counter
    // ---------------------------------------------------------------------

    deoxys_bc_128_384_setup_base_counters(&(ctx->cipher_ctx), ZCZ_DOMAIN_S, 0);

    // ---------------------------------------------------------------------
    // Compute S_i
    // ---------------------------------------------------------------------

    for (size_t i = 0; i < num_chunks; ++i) {
        tweak = set64(i+1, 0L);

        // ---------------------------------------------------------------------
        // Compute S_i = E_K^{s, 0, i}(S)
        // ---------------------------------------------------------------------

        deoxys_bc_128_384_encrypt(cipher_ctx,
                                  ZCZ_DOMAIN_S,
                                  tweak_counter,
                                  tweak,
                                  ctx->s,
                                  &s_i);

        size_t num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;

        if ((i + 1) == num_chunks) {
            num_di_blocks_in_chunk =
                (num_di_blocks_without_final % (ZCZ_NUM_DI_BLOCKS_IN_CHUNK));

            if (num_di_blocks_in_chunk == 0) {
                num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;
            }
        }

        deoxys_bc_128_384_setup_middle_base(&(ctx->cipher_ctx),
                                            ZCZ_DOMAIN_CENTER,
                                            tweak_counter,
                                            ctx->t);
        // For each chunk, we have j = 1..128 di-blocks.
        // The j variable is also named that way in the paper.
        // size_t j = 0;

        while (num_di_blocks_in_chunk >= ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE) {
            // Compute Z_{i,j} = E_K^{c, k, T}(S_i)
            set_eight_blocks_same_x(s_i, z_i_j);
            deoxys_bc_128_384_encrypt_eight_one(cipher_ctx, k, z_i_j);

            load_eight_blocks(x_i, source_position);      // Load the X_i's
            load_eight_blocks(y_i, (source_position+1));  // Load the R_i's

            vxor_eight(z_i_j, x_i, x_i);  // L'_i = X_i xor Z_{i,j}
            vxor_eight(z_i_j, y_i, y_i);
            vxor_eight_same_x(s_i, y_i, y_i);  // Y_i = R_i xor S_i xor Z_{i,j}

            // Copy the values X_i to the buffer
            store_eight_blocks(target_position, x_i);        // Copy the X_i's
            store_eight_blocks((target_position + 1), y_i);  // Copy the Y_i's

            // Update Y_R
            y_r = gf_2_128_double_eight(y_r, y_i);

            // Update Y_L = Y_i xor L'_i
            vxor_eight(x_i, y_i, y_i);
            y_l = gf_2_128_times_four_eight(y_l, y_i);

            k += ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;
            num_di_blocks_in_chunk -= ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // Used 8
            target_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks fur.
            source_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks fur.
        }

        while (num_di_blocks_in_chunk >= 1) {
            // -----------------------------------------------------------------
            // Compute Z_{i,j} = E_K^{c, 0, k}(S_i)
            // k = (i - 1) * n + j
            // -----------------------------------------------------------------

            deoxys_bc_128_384_encrypt(cipher_ctx,
                                      ZCZ_DOMAIN_CENTER,
                                      k,
                                      ctx->t,
                                      s_i,
                                      z_i_j);

            // -----------------------------------------------------------------
            // Source is at X_i, target is at X_i
            // -----------------------------------------------------------------

            x_i[0] = load(source_position);
            r_i = load((source_position) + 1);

            l_i = vxor(z_i_j[0], x_i[0]);
            y_i[0] = vxor3(r_i, z_i_j[0], s_i);

            store(target_position, l_i);
            store((target_position + 1), y_i[0]);

            // Update Y_L
            gf_2_128_times_four(y_l, y_l, tmp);
            y_l = vxor3(y_l, y_i[0], l_i);

            // Update Y_R
            gf_2_128_double(y_r, y_r, tmp);
            y_r = vxor(y_r, y_i[0]);

            source_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;
            target_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;
            num_di_blocks_in_chunk--;
            k++;
        }
    }

    // ---------------------------------------------------------------------
    // Process Y_L and Y_R.
    // Note: This destroys the previous round tweaks
    // ---------------------------------------------------------------------

    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_YL,
                              num_di_blocks,
                              y_r,
                              y_l,
                              &(ctx->y_l));
    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_YR,
                              num_di_blocks,
                              y_l,
                              y_r,
                              &(ctx->y_r));
}

// ---------------------------------------------------------------------

static void encrypt_bottom_layer(zcz_ctx_t* ctx,
                                 const uint8_t* state,
                                 uint8_t* ciphertext,
                                 const size_t num_di_blocks) {
    __m128i states[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i tweaks[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i* source_position = (__m128i*)state;
    __m128i* target_position = (__m128i*)ciphertext;

    size_t num_di_blocks_remaining = num_di_blocks;
    size_t tweak_counter = 0;
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);
    deoxys_bc_128_384_setup_base_counters(cipher_ctx,
                                          ZCZ_DOMAIN_BOT,
                                          tweak_counter);

    tweak_counter = 1;

    // ---------------------------------------------------------------------
    // Next 8 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE) {
        load_eight_blocks(states, (source_position + 1));  // Y_1 .. Y_8
        load_eight_blocks(tweaks, source_position);        // L'_1  .. L'_8

        // Obtain the values X_i in states
        deoxys_bc_128_384_encrypt_eight_eight(cipher_ctx,
                                              tweak_counter,
                                              tweaks,
                                              states);

        // Copy both L'_i's and R'_i's to the ciphertext
        store_eight_blocks(target_position, tweaks);
        store_eight_blocks((target_position + 1), states);  // Copy the R'_i's

        num_di_blocks_remaining -= ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // We used 8
        target_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        source_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        tweak_counter += ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // Tweak += 8
    }

    // ---------------------------------------------------------------------
    // Tail: 0..7 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > 1) {
        states[0] = load((source_position + 1));
        tweaks[0] = load(source_position);

        deoxys_bc_128_384_encrypt(cipher_ctx,
                                  ZCZ_DOMAIN_BOT,
                                  tweak_counter,
                                  tweaks[0],
                                  states[0],
                                  states);

        // Copy both L'_i and R'_i to the buffer
        store(target_position, tweaks[0]);
        store((target_position + 1), states[0]);

        num_di_blocks_remaining -= 1;  // We used 32 bytes
        target_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        source_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        tweak_counter += 1;
    }
}

// ---------------------------------------------------------------------

static void encrypt_last_di_block_top(zcz_ctx_t* ctx,
                                      const uint8_t* final_full_di_block,
                                      const size_t num_di_blocks) {
    __m128i left_input_block = load(final_full_di_block);
    __m128i right_input_block =
        load((final_full_di_block + ZCZ_NUM_BYTES_IN_BLOCK));
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    __m128i left_output_block = vxor(left_input_block, ctx->x_l);
    __m128i right_output_block = vxor(right_input_block, ctx->x_r);

    deoxys_bc_128_384_encrypt(cipher_ctx,
                          ZCZ_DOMAIN_TOP_LAST,
                          num_di_blocks,
                          right_output_block,
                          left_output_block,
                          &(ctx->s));

    deoxys_bc_128_384_encrypt(cipher_ctx,
                          ZCZ_DOMAIN_S_LAST,
                          num_di_blocks,
                          ctx->s,
                          right_output_block,
                          &(ctx->t));
}

// ---------------------------------------------------------------------

static void encrypt_last_di_block_bottom(zcz_ctx_t* ctx,
                                         const uint8_t* ciphertext,
                                         const size_t num_di_blocks) {
    __m128i left_output_block;
    __m128i right_output_block;

    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);
    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_CENTER_LAST,
                              num_di_blocks,
                              ctx->t,
                              ctx->s,
                              &left_output_block);

    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_BOT_LAST,
                              num_di_blocks,
                              left_output_block,
                              ctx->t,
                              &right_output_block);

    left_output_block = vxor(left_output_block, ctx->y_l);
    right_output_block = vxor(right_output_block, ctx->y_r);

    const uint8_t* left_ciphertext_block =
            ciphertext + (num_di_blocks - 1) * ZCZ_NUM_BYTES_IN_DI_BLOCK;
    const uint8_t* right_ciphertext_block =
            left_ciphertext_block + ZCZ_NUM_BYTES_IN_BLOCK;

    storeu(left_ciphertext_block, left_output_block);
    storeu(right_ciphertext_block, right_output_block);
}

// ---------------------------------------------------------------------
// Decryption component functions
// ---------------------------------------------------------------------

static void decrypt_top_layer(zcz_ctx_t* ctx,
                              const uint8_t* state,
                              uint8_t* plaintext,
                              const size_t num_di_blocks) {
    __m128i states[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i tweaks[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i* source_position = (__m128i*)state;
    __m128i* target_position = (__m128i*)plaintext;

    size_t num_di_blocks_remaining = num_di_blocks;
    size_t tweak_counter = 0;
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    deoxys_bc_128_384_setup_base_counters(cipher_ctx,
                                          ZCZ_DOMAIN_TOP,
                                          tweak_counter);

    tweak_counter = 1;

    // ---------------------------------------------------------------------
    // Next 8 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE) {
        load_eight_blocks(states, source_position);        // L_1 .. L_8
        load_eight_blocks(tweaks, (source_position + 1));  // R_1 .. R_8

        deoxys_bc_128_384_decrypt_eight_eight(cipher_ctx,
                                              tweak_counter,
                                              tweaks,
                                              states);

        // Copy the values X_i to the buffer
        store_eight_blocks(target_position, states);       // Copy the L_i's
        store_eight_blocks((target_position + 1), tweaks);  // Copy the R_i's

        num_di_blocks_remaining -= ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // We used 8
        target_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        source_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        tweak_counter += ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // Tweak += 8
    }

    // ---------------------------------------------------------------------
    // Tail: 0..7 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > 1) {
        states[0] = load(source_position);
        tweaks[0] = load((source_position + 1));

        deoxys_bc_128_384_decrypt(cipher_ctx,
                                  ZCZ_DOMAIN_TOP,
                                  tweak_counter,
                                  tweaks[0],
                                  states[0],
                                  states);

        // Copy X_i || R_i to the buffer
        store(target_position, states[0]);
        store((target_position + 1), tweaks[0]);

        num_di_blocks_remaining -= 1;  // We used 32 bytes
        target_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        source_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        tweak_counter += 1;
    }
}

// ---------------------------------------------------------------------

static void decrypt_middle_layer(zcz_ctx_t* ctx,
                                 uint8_t* state,
                                 const size_t num_di_blocks) {
    __m128i tweaks[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i* source_position = (__m128i*)state;
    __m128i* target_position = (__m128i*)state;

    size_t num_di_blocks_without_final = num_di_blocks;

    if (num_di_blocks > 0) {
        num_di_blocks_without_final--;
    }

    const size_t num_chunks = get_num_chunks(num_di_blocks_without_final);
    size_t k;
    size_t tweak_counter = 0;
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    // ---------------------------------------------------------------------
    // Zeroize the hash values Y_L and Y_R at the beginning
    // ---------------------------------------------------------------------

    __m128i s_i;
    __m128i z_i_j;
    __m128i y_i;
    __m128i l_i;
    __m128i r_i;
    __m128i x_i;

    __m128i x_l = vzero;
    __m128i x_r = vzero;
    __m128i tmp;

    // ---------------------------------------------------------------------
    // Init domain and base counter
    // ---------------------------------------------------------------------

    deoxys_bc_128_384_setup_base_counters(&(ctx->cipher_ctx), ZCZ_DOMAIN_S, 0);

    // ---------------------------------------------------------------------
    // Compute S_i
    // ---------------------------------------------------------------------

    for (size_t i = 0; i < num_chunks; ++i) {
        tweaks[0] = set64(i+1, 0L);
        tweak_counter = 0;

        // ---------------------------------------------------------------------
        // Compute S_i = E_K^{s, 0, i}(S)
        // ---------------------------------------------------------------------

        deoxys_bc_128_384_encrypt(cipher_ctx,
                                  ZCZ_DOMAIN_S,
                                  tweak_counter,
                                  tweaks[0],
                                  ctx->s,
                                  &s_i);

        size_t num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;

        if ((i + 1) == num_chunks) {
            num_di_blocks_in_chunk =
                (num_di_blocks_without_final % (ZCZ_NUM_DI_BLOCKS_IN_CHUNK));

            if (num_di_blocks_in_chunk == 0) {
                num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;
            }
        }

        for (size_t j = 0; j < num_di_blocks_in_chunk; ++j) {
            // -----------------------------------------------------------------
            // Compute Z_{i,j} = E_K^{c, 0, k}(S_i)
            // k = (i - 1) * n + j
            // -----------------------------------------------------------------

            k = i * ZCZ_NUM_DI_BLOCKS_IN_CHUNK + (j+1);
            deoxys_bc_128_384_encrypt(cipher_ctx,
                                      ZCZ_DOMAIN_CENTER,
                                      k,
                                      ctx->t,
                                      s_i,
                                      &z_i_j);

            // -----------------------------------------------------------------
            // Source is at L'_i, target is at L'_i
            // -----------------------------------------------------------------

            l_i = load(source_position);
            y_i = load((source_position) + 1);

            x_i = vxor(z_i_j, l_i);
            r_i = vxor3(y_i, z_i_j, s_i);

            store(target_position, x_i);
            store((target_position + 1), r_i);

            // Update X_R
            gf_2_128_times_four(x_r, x_r, tmp);
            x_r = vxor3(x_r, x_i, r_i);

            // Update X_L
            gf_2_128_double(x_l, x_l, tmp);
            x_l = vxor(x_l, x_i);

            source_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;
            target_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;
        }
    }

    // ---------------------------------------------------------------------
    // Process X_L and X_R.
    // Note: This destroys the previous round tweaks
    // ---------------------------------------------------------------------

    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_XL,
                              num_di_blocks,
                              x_r,
                              x_l,
                              &(ctx->x_l));
    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_XR,
                              num_di_blocks,
                              x_l,
                              x_r,
                              &(ctx->x_r));
}

// ---------------------------------------------------------------------

static void decrypt_bottom_layer(zcz_ctx_t* ctx,
                                 uint8_t* state,
                                 const uint8_t* ciphertext,
                                 const size_t num_di_blocks) {
    deoxys_bc_128_384_setup_base_counters(&(ctx->cipher_ctx),
                                          ZCZ_DOMAIN_BOT,
                                          0);

    __m128i states[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i tweaks[ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE];
    __m128i* source_position = (__m128i*)ciphertext;
    __m128i* target_position = (__m128i*)state;

    size_t num_di_blocks_remaining = num_di_blocks;
    size_t tweak_counter = 0;
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    // Zeroize the hash values X_L and X_R at the beginning
    __m128i y_l = vzero;
    __m128i y_r = vzero;
    __m128i tmp;

    deoxys_bc_128_384_setup_base_counters(cipher_ctx,
                                          ZCZ_DOMAIN_BOT,
                                          tweak_counter);

    tweak_counter = 1;

    // ---------------------------------------------------------------------
    // Next 8 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE) {
        load_eight_blocks(states, (source_position + 1));  // R'_1 .. R'_8
        load_eight_blocks(tweaks, source_position);        // L'_1 .. L'_8

        // Obtain the values Y_i in states
        deoxys_bc_128_384_decrypt_eight_eight(cipher_ctx,
                                              tweak_counter,
                                              tweaks,
                                              states);

        // Copy the values X_i to the buffer
        store_eight_blocks((target_position + 1), states);  // Copy the R'_i's
        store_eight_blocks(target_position, tweaks);        // Copy the L'_i's

        // Update Y_R = Y_R * 2^8 xor Y_1 * 2^7 xor ... Y_7 * 2 xor Y_8
        y_r = gf_2_128_double_eight(y_r, states);

        // states[i] = Y_i xor L'_i
        // Update Y_L = Y_L * (4)^8 xor Y_1 * 4^7 xor ... Y_7 * 4 xor Y_8
        vxor_eight(states, tweaks, states);

        y_l = gf_2_128_times_four_eight(y_l, states);

        num_di_blocks_remaining -= ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // We used 8
        target_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        source_position += ZCZ_NUM_BLOCKS_PER_SEQUENCE;   // 16 blocks further
        tweak_counter += ZCZ_NUM_DI_BLOCKS_PER_SEQUENCE;  // Tweak += 8
    }

    // ---------------------------------------------------------------------
    // Tail: 0..7 di-blocks
    // ---------------------------------------------------------------------

    while (num_di_blocks_remaining > 1) {
        states[0] = load((source_position + 1));
        tweaks[0] = load(source_position);

        deoxys_bc_128_384_decrypt(cipher_ctx,
                                  ZCZ_DOMAIN_BOT,
                                  tweak_counter,
                                  tweaks[0],
                                  states[0],
                                  states);

        // Copy L'_i || Y_i to the buffer
        store(target_position, tweaks[0]);
        store((target_position + 1), states[0]);

        // Update Y_R
        gf_2_128_double(y_r, y_r, tmp);
        y_r = vxor(y_r, states[0]);

        // Update Y_L
        gf_2_128_times_four(y_l, y_l, tmp);
        y_l = vxor3(y_l, states[0], tweaks[0]);

        num_di_blocks_remaining -= 1;  // We used 32 bytes
        target_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        source_position += ZCZ_NUM_BLOCKS_IN_DI_BLOCK;  // 2 blocks further
        tweak_counter += 1;
    }

    // ---------------------------------------------------------------------
    // Process Y_L and Y_R.
    // Note: This destroys the previous round tweaks
    // ---------------------------------------------------------------------

    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_YL,
                              num_di_blocks,
                              y_r,
                              y_l,
                              &(ctx->y_l));
    deoxys_bc_128_384_encrypt(cipher_ctx,
                              ZCZ_DOMAIN_YR,
                              num_di_blocks,
                              y_l,
                              y_r,
                              &(ctx->y_r));
}

// ---------------------------------------------------------------------

static void decrypt_last_di_block_top(zcz_ctx_t* ctx,
                                      uint8_t* plaintext,
                                      const size_t num_di_blocks) {
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    __m128i left_output_block;
    __m128i right_output_block;

    deoxys_bc_128_384_decrypt(cipher_ctx,
                              ZCZ_DOMAIN_S_LAST,
                              num_di_blocks,
                              ctx->s,
                              ctx->t,
                              &right_output_block);

    deoxys_bc_128_384_decrypt(cipher_ctx,
                              ZCZ_DOMAIN_TOP_LAST,
                              num_di_blocks,
                              right_output_block,
                              ctx->s,
                              &left_output_block);

    left_output_block = vxor(left_output_block, ctx->x_l);
    right_output_block = vxor(right_output_block, ctx->x_r);

    uint8_t* left_plaintext_block =
            plaintext + (num_di_blocks - 1) * ZCZ_NUM_BYTES_IN_DI_BLOCK;
    uint8_t* right_plaintext_block =
            left_plaintext_block + ZCZ_NUM_BYTES_IN_BLOCK;

    storeu(left_plaintext_block, left_output_block);
    storeu(right_plaintext_block, right_output_block);
}

// ---------------------------------------------------------------------

static void decrypt_last_di_block_bottom(zcz_ctx_t* ctx,
                                         const uint8_t* final_full_di_block,
                                         const size_t num_di_blocks) {
    __m128i left_input_block = load(final_full_di_block);
    __m128i right_input_block =
        load((final_full_di_block + ZCZ_NUM_BYTES_IN_BLOCK));
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);

    __m128i left_output_block = vxor(left_input_block, ctx->y_l);
    __m128i right_output_block = vxor(right_input_block, ctx->y_r);

    deoxys_bc_128_384_decrypt(cipher_ctx,
                              ZCZ_DOMAIN_BOT_LAST,
                              num_di_blocks,
                              left_output_block,
                              right_output_block,
                              &(ctx->t));

    deoxys_bc_128_384_decrypt(cipher_ctx,
                              ZCZ_DOMAIN_CENTER_LAST,
                              num_di_blocks,
                              ctx->t,
                              left_output_block,
                              &(ctx->s));
}

// ---------------------------------------------------------------------
// Partial APIs
// ---------------------------------------------------------------------

static void encrypt_partial_top_layer(zcz_ctx_t* ctx,
                                      uint8_t* final_full_di_block,
                                      const uint8_t* hash_input,
                                      uint8_t* hash_output) {
    hash(ctx, hash_input, hash_output, ZCZ_COUNTER_PARTIAL_TOP);
    vxor_di_block(final_full_di_block, hash_output);
}

// ---------------------------------------------------------------------

static void encrypt_partial_middle_layer(zcz_ctx_t* ctx,
                                         uint8_t* hash_input,
                                         uint8_t* hash_output) {
    hash(ctx, hash_input, hash_output, ZCZ_COUNTER_PARTIAL_CENTER);
}

// ---------------------------------------------------------------------

static void encrypt_partial_bottom_layer(zcz_ctx_t* ctx,
                                         uint8_t* final_full_di_block,
                                         const uint8_t* hash_input,
                                         uint8_t* hash_output) {
    hash(ctx, hash_input, hash_output, ZCZ_COUNTER_PARTIAL_BOTTOM);
    vxor_di_block(final_full_di_block, hash_output);
}

// ---------------------------------------------------------------------
// Internal APIs
// ---------------------------------------------------------------------

static void internal_zcz_basic_encrypt(zcz_ctx_t* ctx,
                                       const uint8_t* plaintext,
                                       const uint8_t* final_full_di_block,
                                       const size_t num_plaintext_bytes,
                                       uint8_t* ciphertext) {
    const size_t num_di_blocks = get_num_full_di_blocks(num_plaintext_bytes);
    uint8_t* state = (uint8_t*)malloc(num_plaintext_bytes);

    encrypt_top_layer(ctx, state, plaintext, num_di_blocks);
    encrypt_last_di_block_top(ctx, final_full_di_block, num_di_blocks);
    encrypt_middle_layer(ctx, state, num_di_blocks);
    encrypt_bottom_layer(ctx, state, ciphertext, num_di_blocks);
    encrypt_last_di_block_bottom(ctx, ciphertext, num_di_blocks);

    free(state);
}

// ---------------------------------------------------------------------

static void internal_zcz_basic_decrypt(zcz_ctx_t* ctx,
                                       const uint8_t* ciphertext,
                                       const uint8_t* final_full_di_block,
                                       const size_t num_ciphertext_bytes,
                                       uint8_t* plaintext) {
    const size_t num_di_blocks = get_num_full_di_blocks(num_ciphertext_bytes);
    uint8_t* state = (uint8_t*)malloc(num_ciphertext_bytes);

    decrypt_bottom_layer(ctx, state, ciphertext, num_di_blocks);
    decrypt_last_di_block_bottom(ctx, final_full_di_block, num_di_blocks);
    decrypt_middle_layer(ctx, state, num_di_blocks);
    decrypt_top_layer(ctx, state, plaintext, num_di_blocks);
    decrypt_last_di_block_top(ctx, plaintext, num_di_blocks);

    free(state);
}

// ---------------------------------------------------------------------

static void internal_zcz_encrypt(zcz_ctx_t* ctx,
                                 const uint8_t* plaintext,
                                 const size_t num_plaintext_bytes,
                                 uint8_t* ciphertext) {
    const size_t num_full_di_blocks =
        get_num_full_di_blocks(num_plaintext_bytes);

    const size_t num_bytes_in_full_di_blocks =
        num_full_di_blocks * ZCZ_NUM_BYTES_IN_DI_BLOCK;

    const size_t num_remaining_bytes =
        num_plaintext_bytes % ZCZ_NUM_BYTES_IN_DI_BLOCK;

    const size_t start_of_last_full_di_block =
        num_bytes_in_full_di_blocks - ZCZ_NUM_BYTES_IN_DI_BLOCK;

    // ---------------------------------------------------------------------
    // Copy and pad the partial di-block
    // ---------------------------------------------------------------------

    uint8_t padded_final_di_block[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    memcpy(padded_final_di_block,
           plaintext + num_bytes_in_full_di_blocks,
           num_remaining_bytes);

    pad_message(padded_final_di_block,
                num_remaining_bytes,
                ZCZ_NUM_BYTES_IN_DI_BLOCK);

    // ---------------------------------------------------------------------
    // Top layer
    // ---------------------------------------------------------------------

    uint8_t top_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    uint8_t final_full_di_block[ZCZ_NUM_BYTES_IN_DI_BLOCK];

    memcpy(final_full_di_block,
           plaintext + start_of_last_full_di_block,
           ZCZ_NUM_BYTES_IN_DI_BLOCK);

    encrypt_partial_top_layer(ctx,
                              final_full_di_block,
                              padded_final_di_block,
                              top_hash_output);

    // We stored M_l xor H[E,0] in top_hash_output since we need it later
    memcpy(top_hash_output, final_full_di_block, ZCZ_NUM_BYTES_IN_DI_BLOCK);

    // ---------------------------------------------------------------------
    // Perform ZCZ basic encryption on the full di-blocks
    // ---------------------------------------------------------------------

    internal_zcz_basic_encrypt(ctx,
                               plaintext,
                               final_full_di_block,
                               num_bytes_in_full_di_blocks,
                               ciphertext);

    // ---------------------------------------------------------------------
    // Middle layer
    // ---------------------------------------------------------------------

    // Prepare the input to the middle hash and store it into top_hash_output.
    memcpy(final_full_di_block,
           ciphertext + start_of_last_full_di_block,
           ZCZ_NUM_BYTES_IN_DI_BLOCK);

    // Here, we need M_l xor H[E,0] and xor it with the result of the final
    // full di-block of the basic encryption, and store it in top_hash_output.
    // Note: we cannot store it in final_full_di_block since we need that later.

    vxor_di_block(top_hash_output, final_full_di_block);

    uint8_t middle_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    encrypt_partial_middle_layer(ctx,
                                 top_hash_output,
                                 middle_hash_output);

    vxor_di_block(padded_final_di_block, middle_hash_output);

    // ---------------------------------------------------------------------
    // Bottom layer
    // ---------------------------------------------------------------------

    // We have to use exactly as many bytes from the middle-hash output as the
    // partial di-block M_* is long, and pad the rest.

    pad_message(padded_final_di_block,
                num_remaining_bytes,
                ZCZ_NUM_BYTES_IN_DI_BLOCK);

    uint8_t bottom_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    encrypt_partial_bottom_layer(ctx,
                                 final_full_di_block,
                                 padded_final_di_block,
                                 bottom_hash_output);

    // ---------------------------------------------------------------------
    // Copy the partial di-block result to the partial di-block in the
    // ciphertext.
    // ---------------------------------------------------------------------

    memcpy(ciphertext + start_of_last_full_di_block,
           final_full_di_block,
           ZCZ_NUM_BYTES_IN_DI_BLOCK);

    memcpy(ciphertext + num_bytes_in_full_di_blocks,
           padded_final_di_block,
           num_remaining_bytes);
}

// ---------------------------------------------------------------------

static void internal_zcz_decrypt(zcz_ctx_t* ctx,
                                 const uint8_t* ciphertext,
                                 const size_t num_ciphertext_bytes,
                                 uint8_t* plaintext) {
    const size_t num_full_di_blocks =
        get_num_full_di_blocks(num_ciphertext_bytes);

    const size_t num_bytes_in_full_di_blocks =
        num_full_di_blocks * ZCZ_NUM_BYTES_IN_DI_BLOCK;

    const size_t num_remaining_bytes =
        num_ciphertext_bytes % ZCZ_NUM_BYTES_IN_DI_BLOCK;

    const size_t start_of_last_full_di_block =
        num_bytes_in_full_di_blocks - ZCZ_NUM_BYTES_IN_DI_BLOCK;

    // ---------------------------------------------------------------------
    // Copy and pad the partial di-block
    // ---------------------------------------------------------------------

    uint8_t padded_final_di_block[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    memcpy(padded_final_di_block,
           ciphertext + num_bytes_in_full_di_blocks,
           num_remaining_bytes);
    pad_message(padded_final_di_block,
                num_remaining_bytes,
                ZCZ_NUM_BYTES_IN_DI_BLOCK);

    // ---------------------------------------------------------------------
    // Bottom layer
    // ---------------------------------------------------------------------

    uint8_t bottom_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    uint8_t final_full_di_block[ZCZ_NUM_BYTES_IN_DI_BLOCK];

    memcpy(final_full_di_block,
           ciphertext + start_of_last_full_di_block,
           ZCZ_NUM_BYTES_IN_DI_BLOCK);

    encrypt_partial_bottom_layer(ctx,
                                 final_full_di_block,
                                 padded_final_di_block,
                                 bottom_hash_output);

    // Copy the final di-block to XOR it later on
    memcpy(bottom_hash_output, final_full_di_block, ZCZ_NUM_BYTES_IN_DI_BLOCK);

    // ---------------------------------------------------------------------
    // Perform ZCZ basic encryption on the full di-blocks
    // ---------------------------------------------------------------------

    internal_zcz_basic_decrypt(ctx,
                               ciphertext,
                               final_full_di_block,
                               num_bytes_in_full_di_blocks,
                               plaintext);

    // ---------------------------------------------------------------------
    // Middle layer
    // ---------------------------------------------------------------------

    // Prepare the input to the middle hash and store it into top_hash_output.
    memcpy(final_full_di_block,
           plaintext + start_of_last_full_di_block,
           ZCZ_NUM_BYTES_IN_DI_BLOCK);

    // Here, we need M_l xor H[E,0] and xor it with the result of the final
    // full di-block of the basic encryption, and store it in top_hash_output.
    // Note: we cannot store it in final_full_di_block since we need that later.

    vxor_di_block(bottom_hash_output, final_full_di_block);

    uint8_t middle_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    encrypt_partial_middle_layer(ctx,
                                 bottom_hash_output,
                                 middle_hash_output);
    vxor_di_block(padded_final_di_block, middle_hash_output);

    // ---------------------------------------------------------------------
    // Top layer
    // ---------------------------------------------------------------------

    // We have to use exactly as many bytes from the middle-hash output as the
    // partial di-block M_* is long, and pad the rest.

    pad_message(padded_final_di_block,
                num_remaining_bytes,
                ZCZ_NUM_BYTES_IN_DI_BLOCK);

    uint8_t top_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    encrypt_partial_top_layer(ctx,
                              final_full_di_block,
                              padded_final_di_block,
                              top_hash_output);

    // ---------------------------------------------------------------------
    // Copy the partial di-block result to the partial di-block in the
    // plaintext.
    // ---------------------------------------------------------------------

    memcpy(plaintext + start_of_last_full_di_block,
           final_full_di_block,
           ZCZ_NUM_BYTES_IN_DI_BLOCK);

    memcpy(plaintext + num_bytes_in_full_di_blocks,
           padded_final_di_block,
           num_remaining_bytes);
}

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

void zcz_keysetup(zcz_ctx_t* ctx, const zcz_key_t key) {
    deoxys_bc_128_384_ctx_t* cipher_ctx = &(ctx->cipher_ctx);
    deoxys_bc_128_384_setup_key(cipher_ctx, loadu(key));
    deoxys_bc_128_384_setup_decryption_key(cipher_ctx);
}

// ---------------------------------------------------------------------

void zcz_basic_encrypt(zcz_ctx_t* ctx,
                       const uint8_t* plaintext,
                       const size_t num_plaintext_bytes,
                       uint8_t* ciphertext) {
    if (is_length_ok_for_zcz_basic(num_plaintext_bytes)) {
        const size_t start_of_last_full_di_block = num_plaintext_bytes
            - ZCZ_NUM_BYTES_IN_DI_BLOCK;
        const uint8_t* final_full_di_block = plaintext
            + start_of_last_full_di_block;

        internal_zcz_basic_encrypt(ctx,
                                   plaintext,
                                   final_full_di_block,
                                   num_plaintext_bytes,
                                   ciphertext);
    }
}

// ---------------------------------------------------------------------

void zcz_basic_decrypt(zcz_ctx_t* ctx,
                       const uint8_t* ciphertext,
                       const size_t num_ciphertext_bytes,
                       uint8_t* plaintext) {
    if (is_length_ok_for_zcz_basic(num_ciphertext_bytes)) {
        const size_t start_of_last_full_di_block = num_ciphertext_bytes
          - ZCZ_NUM_BYTES_IN_DI_BLOCK;
        const uint8_t* final_full_di_block = ciphertext
          + start_of_last_full_di_block;

        internal_zcz_basic_decrypt(ctx,
                                   ciphertext,
                                   final_full_di_block,
                                   num_ciphertext_bytes,
                                   plaintext);
    }
}

// ---------------------------------------------------------------------

void zcz_encrypt(zcz_ctx_t* ctx,
                 const uint8_t* plaintext,
                 const size_t num_plaintext_bytes,
                 uint8_t* ciphertext) {
    if (is_length_ok_for_zcz_basic(num_plaintext_bytes)) {
        const size_t start_of_last_full_di_block = num_plaintext_bytes
          - ZCZ_NUM_BYTES_IN_DI_BLOCK;
        const uint8_t* final_full_di_block = plaintext
          + start_of_last_full_di_block;

        internal_zcz_basic_encrypt(ctx,
                                   plaintext,
                                   final_full_di_block,
                                   num_plaintext_bytes,
                                   ciphertext);
        return;
    }

    if (!is_length_ok_for_zcz(num_plaintext_bytes)) {
        return;
    }

    internal_zcz_encrypt(ctx, plaintext, num_plaintext_bytes, ciphertext);
}

// ---------------------------------------------------------------------

void zcz_decrypt(zcz_ctx_t* ctx,
                 const uint8_t* ciphertext,
                 const size_t num_ciphertext_bytes,
                 uint8_t* plaintext) {
    if (is_length_ok_for_zcz_basic(num_ciphertext_bytes)) {
        const size_t start_of_last_full_di_block = num_ciphertext_bytes
          - ZCZ_NUM_BYTES_IN_DI_BLOCK;
        const uint8_t* final_full_di_block = ciphertext
          + start_of_last_full_di_block;

        internal_zcz_basic_decrypt(ctx,
                                   ciphertext,
                                   final_full_di_block,
                                   num_ciphertext_bytes,
                                   plaintext);
        return;
    }

    if (!is_length_ok_for_zcz(num_ciphertext_bytes)) {
        return;
    }

    internal_zcz_decrypt(ctx, ciphertext, num_ciphertext_bytes, plaintext);
}
