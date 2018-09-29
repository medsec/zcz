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

#include "aes.h"
#include "deoxysbc.h"
#include "utils.h"

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

static const deoxys_bc_block_t H_PERMUTATION = {
        7, 0, 13, 10, 11, 4, 1, 14, 15, 8, 5, 2, 3, 12, 9, 6
};
static const unsigned char RCON[17] = {
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
        0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
        0x72
};

// ---------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------

static inline void xor_block(deoxys_bc_block_t out,
                             const deoxys_bc_block_t a,
                             const deoxys_bc_block_t b) {
    vxor(out, a, b, DEOXYS_BC_BLOCKLEN);
}

// ---------------------------------------------------------------------
// Deoxys permutations
// ---------------------------------------------------------------------

static inline void permute(deoxys_bc_block_t x, const deoxys_bc_block_t mask) {
    deoxys_bc_block_t tmp;

    for (size_t i = 0; i < DEOXYS_BC_BLOCKLEN; ++i) {
        tmp[i] = x[mask[i]];
    }

    memcpy(x, tmp, DEOXYS_BC_BLOCKLEN);
}

// ---------------------------------------------------------------------

static inline void permute_tweak(deoxys_bc_block_t x) {
    permute(x, H_PERMUTATION);
}

// ---------------------------------------------------------------------

static uint8_t lfsr_two_byte(const uint8_t in) {
    return ((in << 1) & 0xFE) | (((in >> 7) ^ (in >> 5)) & 0x01);
}

// ---------------------------------------------------------------------

static uint8_t lfsr_three_byte(const uint8_t in) {
    return ((in >> 1) & 0x7F) | (((in << 7) ^ (in << 1)) & 0x80);
}

// ---------------------------------------------------------------------

static void lfsr_two(deoxys_bc_block_t out, const deoxys_bc_block_t in) {
    for (int i = 0; i < DEOXYS_BC_BLOCKLEN; ++i) {
        out[i] = lfsr_two_byte(in[i]);
    }
}

// ---------------------------------------------------------------------

static void lfsr_three(deoxys_bc_block_t out, const deoxys_bc_block_t in) {
    for (int i = 0; i < DEOXYS_BC_BLOCKLEN; ++i) {
        out[i] = lfsr_three_byte(in[i]);
    }
}

// ---------------------------------------------------------------------

static void add_round_constants(deoxys_bc_block_t *subkeys,
                                const size_t num_rounds) {
    for (size_t i = 0; i <= num_rounds; ++i) {
        const deoxys_bc_block_t round_constant = {
                1, 2, 4, 8,
                RCON[i], RCON[i], RCON[i], RCON[i],
                0, 0, 0, 0,
                0, 0, 0, 0
        };
        xor_block(subkeys[i], subkeys[i], round_constant);
    }
}

// ---------------------------------------------------------------------

static void setup_decryption_key(const deoxys_bc_block_t *encryption_key,
                                 deoxys_bc_block_t *decryption_key,
                                 const size_t num_rounds) {
    // ---------------------------------------------------------------------
    // Invert the order of subkeys
    // ---------------------------------------------------------------------

    for (size_t i = 0; i <= num_rounds; ++i) {
        memcpy(decryption_key[i], encryption_key[i], DEOXYS_BC_BLOCKLEN);
    }

    // ---------------------------------------------------------------------
    // Apply the inverse MixColumns transformation to all round keys but the
    // last one.
    // ---------------------------------------------------------------------

    for (size_t i = 0; i < num_rounds; ++i) {
        aes_invert_mix_columns(decryption_key[i]);
    }
}

// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

void deoxys_bc_128_128_setup_key(deoxys_bc_128_128_ctx_t *ctx,
                                 const deoxys_bc_key_t key) {
    const size_t num_rounds = DEOXYS_BC_128_128_NUM_ROUNDS;

    // ---------------------------------------------------------------------
    // Expand key
    // ---------------------------------------------------------------------

    deoxys_bc_block_t* subkeys = ctx->encryption_key;
    memcpy(&(subkeys[0]), key, DEOXYS_BC_BLOCKLEN);

    for (size_t i = 0; i < num_rounds; ++i) {
        memcpy(&(subkeys[i + 1]), &(subkeys[i]), DEOXYS_BC_BLOCKLEN);
        permute_tweak(subkeys[i + 1]);
    }

    add_round_constants(subkeys, num_rounds);

    // ---------------------------------------------------------------------
    // Derive decryption tweakeys
    // ---------------------------------------------------------------------

    setup_decryption_key(subkeys, ctx->decryption_key, num_rounds);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_256_setup_key(deoxys_bc_128_256_ctx_t *ctx,
                                 const deoxys_bc_key_t key,
                                 const deoxys_bc_128_256_tweak_t tweak) {
    const size_t num_rounds = DEOXYS_BC_128_256_NUM_ROUNDS;

    // ---------------------------------------------------------------------
    // Expand key
    // ---------------------------------------------------------------------

    deoxys_bc_block_t *subkeys = ctx->encryption_key;
    memcpy(&(subkeys[0]), key, DEOXYS_BC_BLOCKLEN);

    for (size_t i = 0; i < num_rounds; ++i) {
        lfsr_two(subkeys[i + 1], subkeys[i]);
        permute_tweak(subkeys[i + 1]);
    }

    add_round_constants(subkeys, num_rounds);

    // ---------------------------------------------------------------------
    // Expand tweak
    // ---------------------------------------------------------------------

    deoxys_bc_block_t subtweak;
    memcpy(subtweak, tweak, DEOXYS_BC_BLOCKLEN);

    for (size_t i = 0; i <= num_rounds; ++i) {
        xor_block(subkeys[i], subkeys[i], subtweak);
        permute_tweak(subtweak);
    }

    // ---------------------------------------------------------------------
    // Derive decryption tweakeys
    // ---------------------------------------------------------------------

    setup_decryption_key(subkeys, ctx->decryption_key, num_rounds);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_key(deoxys_bc_128_384_ctx_t *ctx,
                                 const deoxys_bc_key_t key,
                                 const deoxys_bc_128_384_tweak_t tweak) {
    const size_t num_rounds = DEOXYS_BC_128_384_NUM_ROUNDS;

    // ---------------------------------------------------------------------
    // Expand key
    // ---------------------------------------------------------------------

    deoxys_bc_block_t *subkeys = ctx->encryption_key;
    memcpy(&(subkeys[0]), key, DEOXYS_BC_BLOCKLEN);

    // print_hex("TK3[0]      ", subkeys[0], 16);

    for (size_t i = 0; i < num_rounds; ++i) {
        lfsr_three(subkeys[i + 1], subkeys[i]);
        permute_tweak(subkeys[i + 1]);
    }

    add_round_constants(subkeys, num_rounds);

    // print_hex("TK3[0] w/ RC", subkeys[0], 16);

    // ---------------------------------------------------------------------
    // Expand tweak
    // ---------------------------------------------------------------------

    deoxys_bc_block_t subtweak1;
    deoxys_bc_block_t subtweak2;

    memcpy(subtweak1, tweak, DEOXYS_BC_BLOCKLEN);
    memcpy(subtweak2, tweak + DEOXYS_BC_BLOCKLEN, DEOXYS_BC_BLOCKLEN);

    // print_hex("TK1[0]      ", subtweak1, 16);
    // print_hex("TK2[0]      ", subtweak2, 16);

    xor_block(subkeys[0], subkeys[0], subtweak1);
    xor_block(subkeys[0], subkeys[0], subtweak2);

    for (size_t i = 1; i <= num_rounds; ++i) {
        permute_tweak(subtweak1);
        permute_tweak(subtweak2);
        lfsr_two(subtweak2, subtweak2);

        xor_block(subkeys[i], subkeys[i], subtweak1);
        xor_block(subkeys[i], subkeys[i], subtweak2);
    }

    // ---------------------------------------------------------------------
    // Derive decryption tweakeys
    // ---------------------------------------------------------------------

    setup_decryption_key(subkeys, ctx->decryption_key, num_rounds);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_128_encrypt(deoxys_bc_128_128_ctx_t *ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t ciphertext) {
    deoxys_bc_128_128_setup_key(ctx, key);

    const size_t num_rounds = DEOXYS_BC_128_128_NUM_ROUNDS;
    deoxys_bc_block_t state;

    xor_block(state, plaintext, ctx->encryption_key[0]);

    for (size_t i = 1; i < num_rounds; ++i) {
        aes_encrypt_round(state, state, ctx->encryption_key[i]);
    }

    aes_encrypt_round(state, ciphertext, ctx->encryption_key[num_rounds]);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_256_encrypt(deoxys_bc_128_256_ctx_t *ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_256_tweak_t tweak,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t ciphertext) {
    deoxys_bc_128_256_setup_key(ctx, key, tweak);

    const size_t num_rounds = DEOXYS_BC_128_256_NUM_ROUNDS;
    deoxys_bc_block_t state;

    xor_block(state, plaintext, ctx->encryption_key[0]);

    for (size_t i = 1; i < num_rounds; ++i) {
        aes_encrypt_round(state, state, ctx->encryption_key[i]);
    }

    aes_encrypt_round(state, ciphertext, ctx->encryption_key[num_rounds]);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt(deoxys_bc_128_384_ctx_t *ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_384_tweak_t tweak,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t ciphertext) {
    deoxys_bc_128_384_setup_key(ctx, key, tweak);

    const size_t num_rounds = DEOXYS_BC_128_384_NUM_ROUNDS;
    deoxys_bc_block_t state;
    xor_block(state, plaintext, ctx->encryption_key[0]);

#ifdef DEBUG
    print_hex(" 0 plain", plaintext, 16);
    print_hex(" 0 state", state, 16);
    print_hex(" 0 tk   ", ctx->encryption_key[0], 16);
#endif

    for (size_t i = 1; i < num_rounds; ++i) {
        aes_encrypt_round(state, state, ctx->encryption_key[i]);

#ifdef DEBUG
        printf("%2zu ", i);
        print_hex("state", state, 16);
        printf("%2zu ", i);
        print_hex("tk   ", ctx->encryption_key[i], 16);
#endif
    }

    aes_encrypt_round(state, ciphertext, ctx->encryption_key[num_rounds]);

#ifdef DEBUG
    printf("%2zu ", num_rounds);
    print_hex("state", ciphertext, 16);
    printf("%2zu ", num_rounds);
    print_hex(" tk  ", ctx->encryption_key[num_rounds], 16);
#endif
}

// ---------------------------------------------------------------------

void deoxys_bc_128_128_decrypt(deoxys_bc_128_128_ctx_t *ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext) {
    deoxys_bc_128_128_setup_key(ctx, key);

    const size_t num_rounds = DEOXYS_BC_128_128_NUM_ROUNDS;
    deoxys_bc_block_t state;

    xor_block(state, ciphertext, ctx->decryption_key[num_rounds]);
    aes_invert_mix_columns(state);

    for (size_t i = num_rounds - 1; i > 0; --i) {
        aes_decrypt_round(state, state, ctx->decryption_key[i]);
    }

    aes_decrypt_round(state, plaintext, ctx->decryption_key[0]);
    aes_mix_columns(plaintext);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_256_decrypt(deoxys_bc_128_256_ctx_t *ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_256_tweak_t tweak,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext) {
    deoxys_bc_128_256_setup_key(ctx, key, tweak);

    const size_t num_rounds = DEOXYS_BC_128_256_NUM_ROUNDS;
    deoxys_bc_block_t state;

    xor_block(state, ciphertext, ctx->decryption_key[num_rounds]);
    aes_invert_mix_columns(state);

    for (size_t i = num_rounds - 1; i > 0; --i) {
        aes_decrypt_round(state, state, ctx->decryption_key[i]);
    }

    aes_decrypt_round(state, plaintext, ctx->decryption_key[0]);
    aes_mix_columns(plaintext);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt(deoxys_bc_128_384_ctx_t *ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_384_tweak_t tweak,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext) {
    deoxys_bc_128_384_setup_key(ctx, key, tweak);

    const size_t num_rounds = DEOXYS_BC_128_384_NUM_ROUNDS;
    deoxys_bc_block_t state;

    xor_block(state, ciphertext, ctx->decryption_key[num_rounds]);

#ifdef DEBUG
    print_hex("16 cipher", ciphertext, 16);
    print_hex("16 deckey", ctx->decryption_key[num_rounds], 16);
    print_hex("16 state ", state, 16);
#endif

    aes_invert_mix_columns(state);

    for (size_t i = num_rounds - 1; i > 0; --i) {
        aes_decrypt_round(state, state, ctx->decryption_key[i]);

#ifdef DEBUG
        printf("%2zu", i);
        print_hex(" state ", state, 16);
        printf("%2zu", i);
        print_hex(" deckey", ctx->decryption_key[i], 16);
#endif
    }

    aes_decrypt_round(state, plaintext, ctx->decryption_key[0]);

#ifdef DEBUG
    printf("%2d ", -1);
    print_hex(" state ", plaintext, 16);
    printf("%2d ", -1);
    print_hex(" deckey", ctx->decryption_key[0], 16);
#endif

    aes_mix_columns(plaintext);

#ifdef DEBUG
    printf("%2d", 0);
    print_hex(" plain ", plaintext, 16);
#endif
}
