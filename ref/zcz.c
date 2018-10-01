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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"
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
// Helper functions
// ---------------------------------------------------------------------

static inline void xor_block(zcz_block_t in_out,
                             const zcz_block_t b) {
    vxor(in_out, in_out, b, ZCZ_NUM_BYTES_IN_BLOCK);
}

// ---------------------------------------------------------------------

static inline void xor_block_three(zcz_block_t out,
                                   const zcz_block_t a,
                                   const zcz_block_t b) {
    vxor(out, a, b, ZCZ_NUM_BYTES_IN_BLOCK);
}

// ---------------------------------------------------------------------

static inline void xor_di_block(uint8_t *in_out,
                                const uint8_t *b) {
    vxor(in_out, in_out, b, ZCZ_NUM_BYTES_IN_DI_BLOCK);
}

// ---------------------------------------------------------------------

static inline void zeroize_block(zcz_block_t x) {
    zeroize(x, ZCZ_NUM_BYTES_IN_BLOCK);
}

// ---------------------------------------------------------------------

static inline void gf_double_block(zcz_block_t block) {
    zcz_block_t out;
    gf_double(out, block, ZCZ_NUM_BYTES_IN_BLOCK);
    memcpy(block, out, ZCZ_NUM_BYTES_IN_BLOCK);
}

// ---------------------------------------------------------------------

static inline void gf_times_four_block(zcz_block_t block) {
    zcz_block_t out;
    gf_times_four(out, block, ZCZ_NUM_BYTES_IN_BLOCK);
    memcpy(block, out, ZCZ_NUM_BYTES_IN_BLOCK);
}

// ---------------------------------------------------------------------
// Primitive functions
// ---------------------------------------------------------------------

static void build_tweak(zcz_tweak_t tweak,
                        const size_t tweak_domain,
                        const size_t tweak_counter,
                        const zcz_block_t tweak_block) {
    zeroize(tweak, ZCZ_NUM_BYTES_IN_DI_BLOCK);
    const uint8_t domain = tweak_domain & 0xFF;
    memcpy(tweak, tweak_block, ZCZ_NUM_BYTES_IN_BLOCK);
    memcpy(tweak + ZCZ_NUM_BYTES_IN_BLOCK, &domain, 1);
    to_le_array(((uint8_t*)tweak) + ZCZ_NUM_BYTES_IN_BLOCK + 8, tweak_counter);
}

// ---------------------------------------------------------------------

static void zcz_primitive_encrypt(zcz_ctx_t* ctx,
                                  const size_t tweak_domain,
                                  const size_t tweak_counter,
                                  const zcz_block_t tweak_block,
                                  const zcz_block_t plaintext,
                                  zcz_block_t ciphertext) {
    zcz_tweak_t tweak;
    build_tweak(tweak, tweak_domain, tweak_counter, tweak_block);

    deoxys_bc_128_384_encrypt(&(ctx->cipher_ctx),
                              ctx->key,
                              tweak,
                              plaintext,
                              ciphertext);
}

// ---------------------------------------------------------------------

static void zcz_primitive_decrypt(zcz_ctx_t* ctx,
                                  const size_t tweak_domain,
                                  const size_t tweak_counter,
                                  const zcz_tweak_t tweak_block,
                                  const zcz_block_t ciphertext,
                                  zcz_block_t plaintext) {
    zcz_tweak_t tweak;
    build_tweak(tweak, tweak_domain, tweak_counter, tweak_block);
    deoxys_bc_128_384_decrypt(&(ctx->cipher_ctx),
                              ctx->key,
                              tweak,
                              ciphertext,
                              plaintext);
}

// ---------------------------------------------------------------------
// Scheme functions
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
    const uint8_t* u = input;
    const uint8_t* v = input + ZCZ_NUM_BYTES_IN_BLOCK;

    uint8_t* u_prime = output;
    uint8_t* v_prime = output + ZCZ_NUM_BYTES_IN_BLOCK;

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_PARTIAL,
                          domain,
                          v,
                          u,
                          u_prime);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_PARTIAL,
                          domain + 1,
                          v,
                          u,
                          v_prime);
}

// ---------------------------------------------------------------------
// Encryption component functions
// ---------------------------------------------------------------------

static void encrypt_top_layer(zcz_ctx_t* ctx,
                              uint8_t* state,
                              const uint8_t* plaintext,
                              const size_t num_di_blocks) {
    const uint8_t* left_input_block = plaintext;
    const uint8_t* right_input_block = plaintext + ZCZ_NUM_BYTES_IN_BLOCK;

    uint8_t* left_output_block = state;
    uint8_t* right_output_block = state + ZCZ_NUM_BYTES_IN_BLOCK;

    zcz_block_t x_l;
    zcz_block_t x_r;
    zeroize_block(x_l);
    zeroize_block(x_r);

    for (size_t i = 0; i < num_di_blocks-1; ++i) {
        zcz_primitive_encrypt(ctx,
                              ZCZ_DOMAIN_TOP,
                              i+1,
                              right_input_block,
                              left_input_block,
                              left_output_block);
        memcpy(right_output_block, right_input_block, ZCZ_NUM_BYTES_IN_BLOCK);

        gf_double_block(x_l);                // X_L = X_L * 2
        xor_block(x_l, left_output_block);  // X_L = X_L xor X_i

        gf_times_four_block(x_r);            // X_R = X_R * 4

        xor_block(x_r, left_output_block);
        xor_block(x_r, right_input_block);  // X_R = X_R xor (X_i xor R_i)

        left_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        left_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
    }

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_XL,
                          num_di_blocks,
                          x_r,
                          x_l,
                          ctx->x_l);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_XR,
                          num_di_blocks,
                          x_l,
                          x_r,
                          ctx->x_r);
}

// ---------------------------------------------------------------------

static void encrypt_middle_layer(zcz_ctx_t* ctx,
                                 uint8_t* state,
                                 const size_t num_di_blocks) {
    size_t num_di_blocks_without_final = num_di_blocks;

    if (num_di_blocks > 0) {
        num_di_blocks_without_final--;
    }

    const size_t num_chunks = get_num_chunks(num_di_blocks_without_final);

    uint8_t* left_output_block = state;
    uint8_t* right_output_block = state + ZCZ_NUM_BYTES_IN_BLOCK;

    zcz_block_t y_l;
    zcz_block_t y_r;
    zeroize_block(y_l);
    zeroize_block(y_r);

    for (size_t i = 0; i < num_chunks; ++i) {
        zcz_block_t s_i;

        // The tweak is (16 bytes): 0000 0000 i7i6i5i4 i3i2i1i0,
        // where i7..i0 are the bytes of the 64-bit counter i.
        zcz_block_t tweak;
        zeroize_block(tweak);
        to_le_array(((uint8_t*)tweak) + ZCZ_NUM_BYTES_IN_BLOCK - 8, i + 1);

        zcz_primitive_encrypt(ctx,
                              ZCZ_DOMAIN_S,
                              0,
                              tweak,
                              ctx->s,
                              s_i);

        size_t num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;

        if ((i + 1) == num_chunks) {
            num_di_blocks_in_chunk =
                (num_di_blocks_without_final % (ZCZ_NUM_DI_BLOCKS_IN_CHUNK));

            if (num_di_blocks_in_chunk == 0) {
                num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;
            }
        }

        for (size_t j = 0; j < num_di_blocks_in_chunk; ++j) {
            zcz_block_t z_i_j;
            zcz_primitive_encrypt(ctx,
                                  ZCZ_DOMAIN_CENTER,
                                  i * ZCZ_NUM_DI_BLOCKS_IN_CHUNK + (j+1),
                                  ctx->t,
                                  s_i,
                                  z_i_j);

            xor_block(left_output_block, z_i_j);  // L'_i = X_i ^ Z_{i,j}
            xor_block(right_output_block, z_i_j);
            xor_block(right_output_block, s_i);   // Y_i = R_i ^ Z_{i,j} ^ S_i

            gf_double_block(y_r);                 // Y_R = Y_R * 2
            xor_block(y_r, right_output_block);  // Y_R = Y_R ^ Y_i

            gf_times_four_block(y_l);             // Y_L = Y_L * 4
            xor_block(y_l, right_output_block);
            xor_block(y_l, left_output_block);   // Y_L = Y_L ^ (Y_i ^ L'_i)

            left_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
            right_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        }
    }

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_YL,
                          num_di_blocks,
                          y_r,
                          y_l,
                          ctx->y_l);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_YR,
                          num_di_blocks,
                          y_l,
                          y_r,
                          ctx->y_r);
}

// ---------------------------------------------------------------------

static void encrypt_bottom_layer(zcz_ctx_t* ctx,
                                 const uint8_t* state,
                                 uint8_t* ciphertext,
                                 const size_t num_di_blocks) {
    const uint8_t* left_input_block = state;
    const uint8_t* right_input_block = state + ZCZ_NUM_BYTES_IN_BLOCK;

    uint8_t* left_output_block = ciphertext;
    uint8_t* right_output_block = ciphertext + ZCZ_NUM_BYTES_IN_BLOCK;

    for (size_t i = 0; i < num_di_blocks-1; ++i) {
        zcz_primitive_encrypt(ctx,
                              ZCZ_DOMAIN_BOT,
                              i+1,
                              left_input_block,
                              right_input_block,
                              right_output_block);
        memcpy(left_output_block, left_input_block, ZCZ_NUM_BYTES_IN_BLOCK);

        left_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        left_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
    }
}

// ---------------------------------------------------------------------

static void encrypt_last_di_block_top(zcz_ctx_t* ctx,
                                      const uint8_t* final_full_di_block,
                                      const size_t num_di_blocks) {
    const uint8_t* left_input_block = final_full_di_block;
    const uint8_t* right_input_block = final_full_di_block
        + ZCZ_NUM_BYTES_IN_BLOCK;

    zcz_block_t left_output_block;
    zcz_block_t right_output_block;

    xor_block_three(left_output_block, left_input_block, ctx->x_l);
    xor_block_three(right_output_block, right_input_block, ctx->x_r);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_TOP_LAST,
                          num_di_blocks,
                          right_output_block,
                          left_output_block,
                          ctx->s);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_S_LAST,
                          num_di_blocks,
                          ctx->s,
                          right_output_block,
                          ctx->t);
}

// ---------------------------------------------------------------------

static void encrypt_last_di_block_bottom(zcz_ctx_t* ctx,
                                         uint8_t* ciphertext,
                                         const size_t num_di_blocks) {
    zcz_block_t left_output_block;
    zcz_block_t right_output_block;

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_CENTER_LAST,
                          num_di_blocks,
                          ctx->t,
                          ctx->s,
                          left_output_block);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_BOT_LAST,
                          num_di_blocks,
                          left_output_block,
                          ctx->t,
                          right_output_block);

    uint8_t* left_ciphertext_block = ciphertext
            + (num_di_blocks - 1) * ZCZ_NUM_BYTES_IN_DI_BLOCK;
    uint8_t* right_ciphertext_block = ciphertext
            + (num_di_blocks - 1) * ZCZ_NUM_BYTES_IN_DI_BLOCK
            + ZCZ_NUM_BYTES_IN_BLOCK;

    xor_block_three(left_ciphertext_block, left_output_block, ctx->y_l);
    xor_block_three(right_ciphertext_block, right_output_block, ctx->y_r);
}

// ---------------------------------------------------------------------
// Decryption component functions
// ---------------------------------------------------------------------

static void decrypt_top_layer(zcz_ctx_t* ctx,
                              const uint8_t* state,
                              uint8_t* plaintext,
                              const size_t num_di_blocks) {
    const uint8_t* left_input_block = state;
    const uint8_t* right_input_block = state + ZCZ_NUM_BYTES_IN_BLOCK;

    uint8_t* left_output_block = plaintext;
    uint8_t* right_output_block = plaintext + ZCZ_NUM_BYTES_IN_BLOCK;

    for (size_t i = 0; i < num_di_blocks-1; ++i) {
        zcz_primitive_decrypt(ctx,
                              ZCZ_DOMAIN_TOP,
                              i+1,
                              right_input_block,
                              left_input_block,
                              left_output_block);
        memcpy(right_output_block, right_input_block, ZCZ_NUM_BYTES_IN_BLOCK);

        left_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        left_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
    }
}

// ---------------------------------------------------------------------

static void decrypt_middle_layer(zcz_ctx_t* ctx,
                                 uint8_t* state,
                                 const size_t num_di_blocks) {
    size_t num_di_blocks_without_final = num_di_blocks;

    if (num_di_blocks > 0) {
        num_di_blocks_without_final--;
    }

    const size_t num_chunks = get_num_chunks(num_di_blocks_without_final);
    uint8_t* left_output_block = state;
    uint8_t* right_output_block = state + ZCZ_NUM_BYTES_IN_BLOCK;

    zcz_block_t x_l;
    zcz_block_t x_r;
    zeroize_block(x_l);
    zeroize_block(x_r);

    for (size_t i = 0; i < num_chunks; ++i) {
        zcz_block_t s_i;

        // The tweak is (16 bytes): 0000 0000 i7i6i5i4 i3i2i1i0,
        // where i7..i0 are the bytes of the 64-bit counter i.
        zcz_block_t tweak;
        zeroize_block(tweak);
        to_le_array(((uint8_t*)tweak) + ZCZ_NUM_BYTES_IN_BLOCK - 8, i + 1);

        zcz_primitive_encrypt(ctx,
                              ZCZ_DOMAIN_S,
                              0,
                              tweak,
                              ctx->s,
                              s_i);

        size_t num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;

        if ((i + 1) == num_chunks) {
            num_di_blocks_in_chunk =
                    (num_di_blocks_without_final % ZCZ_NUM_DI_BLOCKS_IN_CHUNK);

            if (num_di_blocks_in_chunk == 0) {
                num_di_blocks_in_chunk = ZCZ_NUM_DI_BLOCKS_IN_CHUNK;
            }
        }

        for (size_t j = 0; j < num_di_blocks_in_chunk; ++j) {
            zcz_block_t z_i_j;
            zcz_primitive_encrypt(ctx,
                                  ZCZ_DOMAIN_CENTER,
                                  i * ZCZ_NUM_DI_BLOCKS_IN_CHUNK + (j+1),
                                  ctx->t,
                                  s_i,
                                  z_i_j);
            xor_block(left_output_block, z_i_j);  // L'_i = X_i ^ Z_{i,j}
            xor_block(right_output_block, z_i_j);
            xor_block(right_output_block, s_i);   // Y_i = R_i ^ Z_{i,j} ^ S_i

            gf_double_block(x_l);                 // X_L = X_L * 2
            xor_block(x_l, left_output_block);   // X_L = X_L ^ X_i

            gf_times_four_block(x_r);             // X_R = X_R * 4
            xor_block(x_r, left_output_block);
            xor_block(x_r, right_output_block);  // X_R = X_R ^ (X_i ^ R_i)

            left_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
            right_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        }
    }

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_XL,
                          num_di_blocks,
                          x_r,
                          x_l,
                          ctx->x_l);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_XR,
                          num_di_blocks,
                          x_l,
                          x_r,
                          ctx->x_r);
}

// ---------------------------------------------------------------------

static void decrypt_bottom_layer(zcz_ctx_t* ctx,
                                 uint8_t* state,
                                 const uint8_t* ciphertext,
                                 const size_t num_di_blocks) {
    const uint8_t* left_input_block = ciphertext;
    const uint8_t* right_input_block = ciphertext + ZCZ_NUM_BYTES_IN_BLOCK;

    uint8_t* left_output_block = state;
    uint8_t* right_output_block = state + ZCZ_NUM_BYTES_IN_BLOCK;

    zcz_block_t y_l;
    zcz_block_t y_r;
    zeroize_block(y_l);
    zeroize_block(y_r);

    for (size_t i = 0; i < num_di_blocks-1; ++i) {
        zcz_primitive_decrypt(ctx,
                              ZCZ_DOMAIN_BOT,
                              i+1,
                              left_input_block,
                              right_input_block,
                              right_output_block);
        memcpy(left_output_block, left_input_block, ZCZ_NUM_BYTES_IN_BLOCK);

        gf_double_block(y_r);                  // Y_R = Y_R * 2
        xor_block(y_r, right_output_block);   // Y_R = Y_R xor Y_i

        gf_times_four_block(y_l);              // Y_L = Y_L * 4
        xor_block(y_l, right_output_block);
        xor_block(y_l, left_output_block);    // Y_L = Y_L xor (Y_i xor L'_i)

        left_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_input_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        left_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
        right_output_block += ZCZ_NUM_BYTES_IN_DI_BLOCK;
    }

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_YL,
                          num_di_blocks,
                          y_r,
                          y_l,
                          ctx->y_l);

    zcz_primitive_encrypt(ctx,
                          ZCZ_DOMAIN_YR,
                          num_di_blocks,
                          y_l,
                          y_r,
                          ctx->y_r);
}

// ---------------------------------------------------------------------

static void decrypt_last_di_block_top(zcz_ctx_t* ctx,
                                      uint8_t* plaintext,
                                      const size_t num_di_blocks) {
    zcz_block_t left_output_block;
    zcz_block_t right_output_block;

    zcz_primitive_decrypt(ctx,
                          ZCZ_DOMAIN_S_LAST,
                          num_di_blocks,
                          ctx->s,
                          ctx->t,
                          right_output_block);

    zcz_primitive_decrypt(ctx,
                          ZCZ_DOMAIN_TOP_LAST,
                          num_di_blocks,
                          right_output_block,
                          ctx->s,
                          left_output_block);

    uint8_t* left_plaintext_block =
            plaintext + (num_di_blocks - 1) * ZCZ_NUM_BYTES_IN_DI_BLOCK;
    uint8_t* right_plaintext_block =
            left_plaintext_block + ZCZ_NUM_BYTES_IN_BLOCK;

    xor_block_three(left_plaintext_block, left_output_block, ctx->x_l);
    xor_block_three(right_plaintext_block, right_output_block, ctx->x_r);
}

// ---------------------------------------------------------------------

static void decrypt_last_di_block_bottom(zcz_ctx_t* ctx,
                                         const uint8_t* final_full_di_block,
                                         const size_t num_di_blocks) {
    zcz_block_t left_output_block;
    zcz_block_t right_output_block;

    const uint8_t* left_ciphertext_block = final_full_di_block;
    const uint8_t* right_ciphertext_block = final_full_di_block
        + ZCZ_NUM_BYTES_IN_BLOCK;

    xor_block_three(left_output_block, left_ciphertext_block, ctx->y_l);
    xor_block_three(right_output_block, right_ciphertext_block, ctx->y_r);

    zcz_primitive_decrypt(ctx,
                          ZCZ_DOMAIN_BOT_LAST,
                          num_di_blocks,
                          left_output_block,
                          right_output_block,
                          ctx->t);

    zcz_primitive_decrypt(ctx,
                          ZCZ_DOMAIN_CENTER_LAST,
                          num_di_blocks,
                          ctx->t,
                          left_output_block,
                          ctx->s);
}

// ---------------------------------------------------------------------

static void encrypt_partial_top_layer(zcz_ctx_t* ctx,
                                      uint8_t* final_full_di_block,
                                      const uint8_t* hash_input,
                                      uint8_t* hash_output) {
    hash(ctx, hash_input, hash_output, ZCZ_COUNTER_PARTIAL_TOP);
    xor_di_block(final_full_di_block, hash_output);
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
    xor_di_block(final_full_di_block, hash_output);
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

    xor_di_block(top_hash_output, final_full_di_block);

    uint8_t middle_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    encrypt_partial_middle_layer(ctx,
                                 top_hash_output,
                                 middle_hash_output);

    xor_di_block(padded_final_di_block, middle_hash_output);

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

    xor_di_block(bottom_hash_output, final_full_di_block);

    uint8_t middle_hash_output[ZCZ_NUM_BYTES_IN_DI_BLOCK];
    encrypt_partial_middle_layer(ctx,
                                 bottom_hash_output,
                                 middle_hash_output);

    xor_di_block(padded_final_di_block, middle_hash_output);

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
    memcpy(ctx->key, key, ZCZ_NUM_KEY_BYTES);
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
