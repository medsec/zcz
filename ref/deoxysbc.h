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

#include <stdint.h>


// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

#define DEOXYS_BC_BLOCKLEN                16
#define DEOXYS_BC_128_KEYLEN              16
#define DEOXYS_BC_128_256_TWEAK_LEN       16
#define DEOXYS_BC_128_384_TWEAK_LEN       32

#define DEOXYS_BC_128_128_NUM_ROUNDS      12
#define DEOXYS_BC_128_256_NUM_ROUNDS      14
#define DEOXYS_BC_128_384_NUM_ROUNDS      16

#define DEOXYS_BC_128_128_NUM_ROUND_KEYS  (DEOXYS_BC_128_128_NUM_ROUNDS+1)
#define DEOXYS_BC_128_256_NUM_ROUND_KEYS  (DEOXYS_BC_128_256_NUM_ROUNDS+1)
#define DEOXYS_BC_128_384_NUM_ROUND_KEYS  (DEOXYS_BC_128_384_NUM_ROUNDS+1)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

typedef uint8_t deoxys_bc_block_t[DEOXYS_BC_BLOCKLEN];
typedef uint8_t deoxys_bc_key_t[DEOXYS_BC_128_KEYLEN];
typedef uint8_t deoxys_bc_128_256_tweak_t[DEOXYS_BC_128_256_TWEAK_LEN];
typedef uint8_t deoxys_bc_128_384_tweak_t[DEOXYS_BC_128_384_TWEAK_LEN];

typedef deoxys_bc_block_t
    deoxys_bc_128_128_expanded_key_t[DEOXYS_BC_128_128_NUM_ROUND_KEYS];
typedef deoxys_bc_block_t
    deoxys_bc_128_256_expanded_key_t[DEOXYS_BC_128_256_NUM_ROUND_KEYS];
typedef deoxys_bc_block_t
    deoxys_bc_128_384_expanded_key_t[DEOXYS_BC_128_384_NUM_ROUND_KEYS];

typedef struct {
    deoxys_bc_128_128_expanded_key_t encryption_key;
    deoxys_bc_128_128_expanded_key_t decryption_key;
} deoxys_bc_128_128_ctx_t;

typedef struct {
    deoxys_bc_128_256_expanded_key_t encryption_key;
    deoxys_bc_128_256_expanded_key_t decryption_key;
} deoxys_bc_128_256_ctx_t;

typedef struct {
    deoxys_bc_128_384_expanded_key_t encryption_key;
    deoxys_bc_128_384_expanded_key_t decryption_key;
} deoxys_bc_128_384_ctx_t;

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

void deoxys_bc_128_128_setup_key(deoxys_bc_128_128_ctx_t* ctx,
                                 const deoxys_bc_key_t key);

void deoxys_bc_128_256_setup_key(deoxys_bc_128_256_ctx_t* ctx,
                                 const deoxys_bc_key_t key,
                                 const deoxys_bc_128_256_tweak_t tweak);

void deoxys_bc_128_384_setup_key(deoxys_bc_128_384_ctx_t* ctx,
                                 const deoxys_bc_key_t key,
                                 const deoxys_bc_128_384_tweak_t tweak);

// ---------------------------------------------------------------------

void deoxys_bc_128_128_encrypt(deoxys_bc_128_128_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t ciphertext);

void deoxys_bc_128_256_encrypt(deoxys_bc_128_256_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_256_tweak_t tweak,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t ciphertext);

void deoxys_bc_128_384_encrypt(deoxys_bc_128_384_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_384_tweak_t tweak,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t ciphertext);

// ---------------------------------------------------------------------

void deoxys_bc_128_128_decrypt(deoxys_bc_128_128_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext);

void deoxys_bc_128_256_decrypt(deoxys_bc_128_256_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_256_tweak_t tweak,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext);

void deoxys_bc_128_384_decrypt(deoxys_bc_128_384_ctx_t* ctx,
                               const deoxys_bc_key_t key,
                               const deoxys_bc_128_384_tweak_t tweak,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t plaintext);

// ---------------------------------------------------------------------

#endif  // _DEOXYS_BC_H_
