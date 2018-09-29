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
#ifndef _ZCZ_H_
#define _ZCZ_H_

#include <stddef.h>
#include <stdint.h>
#include "deoxysbc.h"

// ---------------------------------------------------------------------
// Domain Constants
// ---------------------------------------------------------------------

#define ZCZ_DOMAIN_TOP           0
#define ZCZ_DOMAIN_BOT           1
#define ZCZ_DOMAIN_CENTER        2
#define ZCZ_DOMAIN_S             3

#define ZCZ_DOMAIN_TOP_LAST      4
#define ZCZ_DOMAIN_CENTER_LAST   5
#define ZCZ_DOMAIN_BOT_LAST      6
#define ZCZ_DOMAIN_S_LAST        7

#define ZCZ_DOMAIN_XL            8
#define ZCZ_DOMAIN_XR            9
#define ZCZ_DOMAIN_YL           10
#define ZCZ_DOMAIN_YR           11

#define ZCZ_DOMAIN_PARTIAL      12

#define ZCZ_COUNTER_PARTIAL_TOP      0
#define ZCZ_COUNTER_PARTIAL_CENTER   2
#define ZCZ_COUNTER_PARTIAL_BOTTOM   4

#define ZCZ_NUM_BLOCKS_IN_DI_BLOCK       2
#define ZCZ_NUM_BYTES_IN_BLOCK           DEOXYS_BC_BLOCKLEN
#define ZCZ_NUM_KEY_BYTES                DEOXYS_BC_128_KEYLEN
#define ZCZ_NUM_BYTES_IN_DI_BLOCK\
    (ZCZ_NUM_BLOCKS_IN_DI_BLOCK * ZCZ_NUM_BYTES_IN_BLOCK)
#define ZCZ_MIN_NUM_MESSAGE_BYTES        ZCZ_NUM_BYTES_IN_DI_BLOCK
#define ZCZ_NUM_DI_BLOCKS_IN_CHUNK       (ZCZ_NUM_BYTES_IN_BLOCK * 8)
#define ZCZ_NUM_BYTES_IN_CHUNK\
    (ZCZ_NUM_DI_BLOCKS_IN_CHUNK * ZCZ_NUM_BYTES_IN_DI_BLOCK)
#define ZCZ_BASIC_MAX_NUM_MESSAGE_BYTES\
    (ZCZ_NUM_BYTES_IN_DI_BLOCK * ZCZ_NUM_BYTES_IN_BLOCK * 8)

// ---------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------

typedef deoxys_bc_block_t zcz_block_t;
typedef deoxys_bc_block_t zcz_di_block_t[ZCZ_NUM_BLOCKS_IN_DI_BLOCK];
typedef deoxys_bc_128_384_tweak_t zcz_tweak_t;
typedef deoxys_bc_key_t zcz_key_t;

typedef struct {
    deoxys_bc_128_384_ctx_t cipher_ctx;
    deoxys_bc_key_t key;
    zcz_block_t s;
    zcz_block_t t;
    zcz_block_t x_l;
    zcz_block_t x_r;
    zcz_block_t y_l;
    zcz_block_t y_r;
} zcz_ctx_t;

// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

void zcz_keysetup(zcz_ctx_t* ctx, const zcz_key_t key);

// ---------------------------------------------------------------------

void zcz_basic_encrypt(zcz_ctx_t* ctx,
                       const uint8_t* plaintext,
                       const size_t num_plaintext_bytes,
                       uint8_t* ciphertext);

// ---------------------------------------------------------------------

void zcz_basic_decrypt(zcz_ctx_t* ctx,
                       const uint8_t* ciphertext,
                       const size_t num_ciphertext_bytes,
                       uint8_t* plaintext);

// ---------------------------------------------------------------------

void zcz_encrypt(zcz_ctx_t* ctx,
                 const uint8_t* plaintext,
                 const size_t num_plaintext_bytes,
                 uint8_t* ciphertext);

// ---------------------------------------------------------------------

void zcz_decrypt(zcz_ctx_t* ctx,
                 const uint8_t* ciphertext,
                 const size_t num_ciphertext_bytes,
                 uint8_t* plaintext);

// ---------------------------------------------------------------------

#endif  // _ZCZ_H_
