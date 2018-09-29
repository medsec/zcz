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
#ifndef _AES_H_
#define _AES_H_

// ---------------------------------------------------------------------

#include <stdint.h>

// ---------------------------------------------------------------------

#define AES_BLOCK_LEN   16

// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

void aes_encrypt_round(const uint8_t in[AES_BLOCK_LEN],
                       uint8_t out[AES_BLOCK_LEN],
                       const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_encrypt_last_round(const uint8_t in[AES_BLOCK_LEN],
                            uint8_t out[AES_BLOCK_LEN],
                            const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_encrypt_round_tweaked(const uint8_t in[AES_BLOCK_LEN],
                               uint8_t out[AES_BLOCK_LEN],
                               const uint8_t tweak[AES_BLOCK_LEN],
                               const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_encrypt_last_round_tweaked(const uint8_t in[AES_BLOCK_LEN],
                                    uint8_t out[AES_BLOCK_LEN],
                                    const uint8_t tweak[AES_BLOCK_LEN],
                                    const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_decrypt_round(const uint8_t in[AES_BLOCK_LEN],
                       uint8_t out[AES_BLOCK_LEN],
                       const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_decrypt_last_round(const uint8_t in[AES_BLOCK_LEN],
                            uint8_t out[AES_BLOCK_LEN],
                            const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_decrypt_round_tweaked(const uint8_t in[AES_BLOCK_LEN],
                               uint8_t out[AES_BLOCK_LEN],
                               const uint8_t tweak[AES_BLOCK_LEN],
                               const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_decrypt_last_round_tweaked(const uint8_t in[AES_BLOCK_LEN],
                                    uint8_t out[AES_BLOCK_LEN],
                                    const uint8_t tweak[AES_BLOCK_LEN],
                                    const uint8_t subkey[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_mix_columns(uint8_t in[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

void aes_invert_mix_columns(uint8_t in[AES_BLOCK_LEN]);

// ---------------------------------------------------------------------

#endif  // _AES_H_
