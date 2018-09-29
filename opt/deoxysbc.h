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
#ifndef _DEOXYS_BC_H_
#define _DEOXYS_BC_H_

#include <emmintrin.h>
#include <immintrin.h>
#include <stdint.h>

#include "align.h"


// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

#define DEOXYS_BC_BLOCKLEN                16
#define DEOXYS_BC_128_KEYLEN              16

#define DEOXYS_BC_128_128_NUM_ROUNDS      12
#define DEOXYS_BC_128_256_NUM_ROUNDS      14
#define DEOXYS_BC_128_384_NUM_ROUNDS      16

#define DEOXYS_BC_128_128_NUM_ROUND_KEYS  (DEOXYS_BC_128_128_NUM_ROUNDS+1)
#define DEOXYS_BC_128_256_NUM_ROUND_KEYS  (DEOXYS_BC_128_256_NUM_ROUNDS+1)
#define DEOXYS_BC_128_384_NUM_ROUND_KEYS  (DEOXYS_BC_128_384_NUM_ROUNDS+1)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

ALIGN(16)
typedef __m128i deoxys_bc_block_t;
ALIGN(16)
typedef __m128i deoxys_bc_key_t;
ALIGN(16)
typedef __m128i deoxys_bc_128_256_tweak_t;
ALIGN(16)
typedef __m128i deoxys_bc_128_384_tweak_t[2];

ALIGN(16)
typedef deoxys_bc_block_t
    deoxys_bc_128_128_expanded_key_t[DEOXYS_BC_128_128_NUM_ROUND_KEYS];
ALIGN(16)
typedef deoxys_bc_block_t
    deoxys_bc_128_256_expanded_key_t[DEOXYS_BC_128_256_NUM_ROUND_KEYS];
ALIGN(16)
typedef deoxys_bc_block_t
    deoxys_bc_128_384_expanded_key_t[DEOXYS_BC_128_384_NUM_ROUND_KEYS];

ALIGN(16)
typedef struct {
    deoxys_bc_128_128_expanded_key_t round_keys;
} deoxys_bc_128_128_ctx_t;

ALIGN(16)
typedef struct {
    deoxys_bc_128_256_expanded_key_t round_tweaks;
    deoxys_bc_128_256_expanded_key_t round_keys;
} deoxys_bc_128_256_ctx_t;

ALIGN(16)
typedef struct {
    __m128i base_counters[DEOXYS_BC_128_384_NUM_ROUND_KEYS];
    __m128i round_tweaks[DEOXYS_BC_128_384_NUM_ROUND_KEYS];
    deoxys_bc_128_384_expanded_key_t round_keys;
    deoxys_bc_128_384_expanded_key_t decryption_keys;
    deoxys_bc_128_384_expanded_key_t combined_round_keys;
    deoxys_bc_128_384_expanded_key_t combined_decryption_keys;
} deoxys_bc_128_384_ctx_t;

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

void deoxys_bc_128_128_setup_key(deoxys_bc_128_128_ctx_t* ctx,
                                 const deoxys_bc_key_t key);

// ---------------------------------------------------------------------

void deoxys_bc_128_256_setup_key(deoxys_bc_128_256_ctx_t* ctx,
                                 const deoxys_bc_key_t key);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_key(deoxys_bc_128_384_ctx_t* ctx,
                                 const deoxys_bc_key_t key);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_decryption_key(deoxys_bc_128_384_ctx_t* ctx);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_base_counters(deoxys_bc_128_384_ctx_t* ctx,
                                           const uint8_t tweak_domain,
                                           const size_t tweak_counter);

// ---------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------

void deoxys_bc_128_128_encrypt(deoxys_bc_128_128_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t* ciphertext);

// ---------------------------------------------------------------------

void deoxys_bc_128_256_encrypt(deoxys_bc_128_256_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_256_tweak_t tweak,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t* ciphertext);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt(deoxys_bc_128_384_ctx_t* ctx,
                               const uint8_t tweak_domain,
                               const size_t tweak_counter,
                               const deoxys_bc_block_t tweak_block,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t* ciphertext);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_four(deoxys_bc_128_384_ctx_t* ctx,
                                    const size_t tweak_counter,
                                    const __m256i tweak_blocks[2],
                                    deoxys_bc_block_t states[4]);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_eight(deoxys_bc_128_384_ctx_t* ctx,
                                    const size_t tweak_counter,
                                    const __m256i tweak_blocks[4],
                                    deoxys_bc_block_t states[8]);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_eight_eight(deoxys_bc_128_384_ctx_t* ctx,
                                           const size_t tweak_counter,
                                           const __m128i tweak_blocks[8],
                                           __m128i states[8]);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_middle_base(deoxys_bc_128_384_ctx_t* ctx,
                                         const uint8_t tweak_domain,
                                         const size_t tweak_counter,
                                         const __m128i tweak_block);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_eight_one(deoxys_bc_128_384_ctx_t* ctx,
                                         const size_t tweak_counter,
                                         __m128i states[8]);

// ---------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------

void deoxys_bc_128_128_decrypt(deoxys_bc_128_128_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext);

// ---------------------------------------------------------------------

void deoxys_bc_128_256_decrypt(deoxys_bc_128_256_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_256_tweak_t tweak,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt(deoxys_bc_128_384_ctx_t* ctx,
                               const uint8_t tweak_domain,
                               const size_t tweak_counter,
                               const deoxys_bc_block_t tweak_block,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t* plaintext);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt_four(deoxys_bc_128_384_ctx_t* ctx,
                                    const size_t tweak_counter,
                                    __m256i tweak_blocks[2],
                                    deoxys_bc_block_t states[4]);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt_eight(deoxys_bc_128_384_ctx_t* ctx,
                                    const size_t tweak_counter,
                                    __m256i tweak_blocks[4],
                                    deoxys_bc_block_t states[8]);

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt_eight_eight(deoxys_bc_128_384_ctx_t* ctx,
                                           const size_t tweak_counter,
                                           const __m128i tweak_blocks[8],
                                           __m128i states[8]);

// ---------------------------------------------------------------------

#endif  // _DEOXYS_BC_H_
