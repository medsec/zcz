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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "deoxysbc.h"
#include "utils-opt.h"


// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

// Sets only LSB of each byte
// Sets only MSB of each byte
#define MSB_MASK            set8(0x80)
#define ONEB_MASK           set8(0x1b)

#define H_PERMUTATION_1\
    setr8(0x07, 0x00, 0x0d, 0x0a, 0x0b, 0x04, 0x01, 0x0e, \
          0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06)
#define H_PERMUTATION_2\
    setr8(0x0e, 0x07, 0x0c, 0x05, 0x02, 0x0b, 0x00, 0x09, \
          0x06, 0x0f, 0x04, 0x0d, 0x0a, 0x03, 0x08, 0x01)
#define H_PERMUTATION_3\
    setr8(0x09, 0x0e, 0x03, 0x04, 0x0d, 0x02, 0x07, 0x08, \
          0x01, 0x06, 0x0b, 0x0c, 0x05, 0x0a, 0x0f, 0x00)
#define H_PERMUTATION_4\
    setr8(0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
          0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
#define H_PERMUTATION_5\
    setr8(0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06, \
          0x07, 0x00, 0x0d, 0x0a, 0x0b, 0x04, 0x01, 0x0e)
#define H_PERMUTATION_6\
    setr8(0x06, 0x0f, 0x04, 0x0d, 0x0a, 0x03, 0x08, 0x01, \
          0x0e, 0x07, 0x0c, 0x05, 0x02, 0x0b, 0x00, 0x09)
#define H_PERMUTATION_7\
    setr8(0x01, 0x06, 0x0b, 0x0c, 0x05, 0x0a, 0x0f, 0x00, \
          0x09, 0x0e, 0x03, 0x04, 0x0d, 0x02, 0x07, 0x08)
#define H_PERMUTATION_8\
    setr8(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)

static const unsigned char RCON[17] = {
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72
};

#define BYTE_8_MASK       setr8(0, 0, 0, 0, 0, 0, 0, 0, \
                                0xFF, 0, 0, 0, 0, 0, 0, 0)
#define MASK_ONLY_LOBYTES setr8(0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0, \
                                0xFF, 0, 0xFF, 0, 0xFF, 0, 0xFF, 0)

// ---------------------------------------------------------------------
// AVX Constants
// ---------------------------------------------------------------------

#define AVX_FIRST_BYTE_MASK \
    avx_setr8(0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
              0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
#define AVX_BYTE_8_MASK \
    avx_setr8(0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0, 0, 0, 0, \
              0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0, 0, 0, 0, 0, 0, 0)

#define AVX_MASK_ONLY_LOBYTES \
    avx_setr8(0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, \
              0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, \
              0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, \
              0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00)

#define VH_PERMUTATION_1\
    avx_setr8(0x07, 0x00, 0x0d, 0x0a, 0x0b, 0x04, 0x01, 0x0e, \
              0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06, \
              0x07, 0x00, 0x0d, 0x0a, 0x0b, 0x04, 0x01, 0x0e, \
              0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06)
#define VH_PERMUTATION_2\
    avx_setr8(0x0e, 0x07, 0x0c, 0x05, 0x02, 0x0b, 0x00, 0x09, \
              0x06, 0x0f, 0x04, 0x0d, 0x0a, 0x03, 0x08, 0x01, \
              0x0e, 0x07, 0x0c, 0x05, 0x02, 0x0b, 0x00, 0x09, \
              0x06, 0x0f, 0x04, 0x0d, 0x0a, 0x03, 0x08, 0x01)
#define VH_PERMUTATION_3\
    avx_setr8(0x09, 0x0e, 0x03, 0x04, 0x0d, 0x02, 0x07, 0x08, \
              0x01, 0x06, 0x0b, 0x0c, 0x05, 0x0a, 0x0f, 0x00, \
              0x09, 0x0e, 0x03, 0x04, 0x0d, 0x02, 0x07, 0x08, \
              0x01, 0x06, 0x0b, 0x0c, 0x05, 0x0a, 0x0f, 0x00)
#define VH_PERMUTATION_4\
    avx_setr8(0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07)
#define VH_PERMUTATION_5\
    avx_setr8(0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06, \
              0x07, 0x00, 0x0d, 0x0a, 0x0b, 0x04, 0x01, 0x0e, \
              0x0f, 0x08, 0x05, 0x02, 0x03, 0x0c, 0x09, 0x06, \
              0x07, 0x00, 0x0d, 0x0a, 0x0b, 0x04, 0x01, 0x0e)
#define VH_PERMUTATION_6\
    avx_setr8(0x06, 0x0f, 0x04, 0x0d, 0x0a, 0x03, 0x08, 0x01, \
              0x0e, 0x07, 0x0c, 0x05, 0x02, 0x0b, 0x00, 0x09, \
              0x06, 0x0f, 0x04, 0x0d, 0x0a, 0x03, 0x08, 0x01, \
              0x0e, 0x07, 0x0c, 0x05, 0x02, 0x0b, 0x00, 0x09)
#define VH_PERMUTATION_7\
    avx_setr8(0x01, 0x06, 0x0b, 0x0c, 0x05, 0x0a, 0x0f, 0x00, \
              0x09, 0x0e, 0x03, 0x04, 0x0d, 0x02, 0x07, 0x08, \
              0x01, 0x06, 0x0b, 0x0c, 0x05, 0x0a, 0x0f, 0x00, \
              0x09, 0x0e, 0x03, 0x04, 0x0d, 0x02, 0x07, 0x08)
#define VH_PERMUTATION_8\
    avx_setr8(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, \
              0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, \
              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)

// ---------------------------------------------------------------------
// Macros
// ---------------------------------------------------------------------

#define permute(x, p)       _mm_shuffle_epi8(x, p)
#define permute_avx(x, y)   _mm256_shuffle_epi8(x, y)
#define permute_tweak(x)    _mm_shuffle_epi8(x, H_PERMUTATION_1)

// ---------------------------------------------------------------------

#define lfsr_two_generic(x, y, tmp, r1, r2, mask) do {\
    tmp = vxor(x, vshift_left(x, 2));\
    y = vxor(vand(mask, vshift_right(tmp, r1)), \
             vandnot(mask, vshift_left(x, r2)));\
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two(x, y) do {\
    lfsr_two_generic(x, y, y, 7, 1, set8(0x01));\
} while (0)

// ---------------------------------------------------------------------

#define lfsr_three(x, y) do {\
    y = vandnot(MSB_MASK , vshift_right(x, 1));\
    y = vxor(y, vand(vxor(vshift_left(x, 1), vshift_left(x, 7)), MSB_MASK));\
} while (0)

// ---------------------------------------------------------------------
// SB^{-1}, SR^{-1}
// SB, SR, MC
// ---------------------------------------------------------------------

#define aes_mix_columns(source, dest, zero) do {\
    dest = vaesdeclast(source, zero);\
    dest = vaesenc(dest, zero);\
} while (0)

// ---------------------------------------------------------------------
// Macros on four blocks in parallel
// ---------------------------------------------------------------------

#define vxor_four(x, y, z) do {\
    z[0] = vxor(x[0], y[0]);\
    z[1] = vxor(x[1], y[1]);\
    z[2] = vxor(x[2], y[2]);\
    z[3] = vxor(x[3], y[3]);\
} while (0)

// ---------------------------------------------------------------------

#define vxor_four_same(x, k) do {\
    x[0] = vxor(x[0], k);\
    x[1] = vxor(x[1], k);\
    x[2] = vxor(x[2], k);\
    x[3] = vxor(x[3], k);\
} while (0)

// ---------------------------------------------------------------------

#define vaesenc_four(x1, x2, x3, x4, k1, k2, k3, k4) do {\
    vaesenc(x1, k1);\
    vaesenc(x2, k2);\
    vaesenc(x3, k3);\
    vaesenc(x4, k4);\
} while (0)

// ---------------------------------------------------------------------

#define vaesdec_four(x1, x2, x3, x4, k1, k2, k3, k4) do {\
    vaesdec(x1, k1);\
    vaesdec(x2, k2);\
    vaesdec(x3, k3);\
    vaesdec(x4, k4);\
} while (0)

// ---------------------------------------------------------------------

#define vaesdeclast_four(x1, x2, x3, x4, k1, k2, k3, k4) do {\
    vaesdeclast(x1, k1);\
    vaesdeclast(x2, k2);\
    vaesdeclast(x3, k3);\
    vaesdeclast(x4, k4);\
} while (0)

// ---------------------------------------------------------------------

#define aes_mix_columns_four(states, zero) do {\
    states[0] = vaesdeclast(states[0], zero);\
    states[1] = vaesdeclast(states[1], zero);\
    states[2] = vaesdeclast(states[2], zero);\
    states[3] = vaesdeclast(states[3], zero);\
    states[0] = vaesenc(states[0], zero);\
    states[1] = vaesenc(states[1], zero);\
    states[2] = vaesenc(states[2], zero);\
    states[3] = vaesenc(states[3], zero);\
} while (0)

// ---------------------------------------------------------------------

#define vinversemc_four(states) do {\
    states[0] = vinversemc(states[0]); \
    states[1] = vinversemc(states[1]); \
    states[2] = vinversemc(states[2]); \
    states[3] = vinversemc(states[3]); \
} while (0)

// ---------------------------------------------------------------------

#define deoxys_enc_round_four(states, round_tweaks, round_key) do {\
    states[0] = vaesenc(states[0], vxor(round_key, round_tweaks[0])); \
    states[1] = vaesenc(states[1], vxor(round_key, round_tweaks[1])); \
    states[2] = vaesenc(states[2], vxor(round_key, round_tweaks[2])); \
    states[3] = vaesenc(states[3], vxor(round_key, round_tweaks[3])); \
} while (0)

// ---------------------------------------------------------------------

#define deoxys_enc_round_four_store(\
    ciphertexts, states, round_tweaks, round_key) do {\
    ciphertexts[0] = vaesenc(states[0], vxor(round_key, round_tweaks[0])); \
    ciphertexts[1] = vaesenc(states[1], vxor(round_key, round_tweaks[1])); \
    ciphertexts[2] = vaesenc(states[2], vxor(round_key, round_tweaks[2])); \
    ciphertexts[3] = vaesenc(states[3], vxor(round_key, round_tweaks[3])); \
} while (0)

// ---------------------------------------------------------------------

#define deoxys_dec_round_four(states, round_tweaks, round_key) do {\
    states[0] = vaesdec(states[0], vxor(round_key, round_tweaks[0])); \
    states[1] = vaesdec(states[1], vxor(round_key, round_tweaks[1])); \
    states[2] = vaesdec(states[2], vxor(round_key, round_tweaks[2])); \
    states[3] = vaesdec(states[3], vxor(round_key, round_tweaks[3])); \
} while (0)

// ---------------------------------------------------------------------

#define deoxys_declast_round_four(\
    plaintexts, states, round_tweaks, round_key) do {\
    plaintexts[0] = vaesdeclast(states[0], vxor(round_key, round_tweaks[0])); \
    plaintexts[1] = vaesdeclast(states[1], vxor(round_key, round_tweaks[1])); \
    plaintexts[2] = vaesdeclast(states[2], vxor(round_key, round_tweaks[2])); \
    plaintexts[3] = vaesdeclast(states[3], vxor(round_key, round_tweaks[3])); \
} while (0)

// ---------------------------------------------------------------------
// Macros on eight blocks in parallel
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

#define vxor_eight_same(x, k) do {\
    x[0] = vxor(x[0], k);\
    x[1] = vxor(x[1], k);\
    x[2] = vxor(x[2], k);\
    x[3] = vxor(x[3], k);\
    x[4] = vxor(x[4], k);\
    x[5] = vxor(x[5], k);\
    x[6] = vxor(x[6], k);\
    x[7] = vxor(x[7], k);\
} while (0)

// ---------------------------------------------------------------------

#define vaesenc_round_eight(states, round_key) do {\
    states[0] = vaesenc(states[0], round_key); \
    states[1] = vaesenc(states[1], round_key); \
    states[2] = vaesenc(states[2], round_key); \
    states[3] = vaesenc(states[3], round_key); \
    states[4] = vaesenc(states[4], round_key); \
    states[5] = vaesenc(states[5], round_key); \
    states[6] = vaesenc(states[6], round_key); \
    states[7] = vaesenc(states[7], round_key); \
} while (0)

// ---------------------------------------------------------------------

#define deoxys_enc_round_eight(states, round_tweaks, round_key) do {\
    states[0] = vaesenc(states[0], vxor(round_key, round_tweaks[0])); \
    states[1] = vaesenc(states[1], vxor(round_key, round_tweaks[1])); \
    states[2] = vaesenc(states[2], vxor(round_key, round_tweaks[2])); \
    states[3] = vaesenc(states[3], vxor(round_key, round_tweaks[3])); \
    states[4] = vaesenc(states[4], vxor(round_key, round_tweaks[4])); \
    states[5] = vaesenc(states[5], vxor(round_key, round_tweaks[5])); \
    states[6] = vaesenc(states[6], vxor(round_key, round_tweaks[6])); \
    states[7] = vaesenc(states[7], vxor(round_key, round_tweaks[7])); \
} while (0)

// ---------------------------------------------------------------------

#define deoxys_dec_round_eight(states, round_tweaks, round_key) do {\
    states[0] = vaesdec(states[0], vxor(round_key, round_tweaks[0])); \
    states[1] = vaesdec(states[1], vxor(round_key, round_tweaks[1])); \
    states[2] = vaesdec(states[2], vxor(round_key, round_tweaks[2])); \
    states[3] = vaesdec(states[3], vxor(round_key, round_tweaks[3])); \
    states[4] = vaesdec(states[4], vxor(round_key, round_tweaks[4])); \
    states[5] = vaesdec(states[5], vxor(round_key, round_tweaks[5])); \
    states[6] = vaesdec(states[6], vxor(round_key, round_tweaks[6])); \
    states[7] = vaesdec(states[7], vxor(round_key, round_tweaks[7])); \
} while (0)

// ---------------------------------------------------------------------

#define deoxys_declast_round_eight(\
    plaintexts, states, round_tweaks, round_key) do {\
    plaintexts[0] = vaesdeclast(states[0], vxor(round_key, round_tweaks[0])); \
    plaintexts[1] = vaesdeclast(states[1], vxor(round_key, round_tweaks[1])); \
    plaintexts[2] = vaesdeclast(states[2], vxor(round_key, round_tweaks[2])); \
    plaintexts[3] = vaesdeclast(states[3], vxor(round_key, round_tweaks[3])); \
    plaintexts[4] = vaesdeclast(states[4], vxor(round_key, round_tweaks[4])); \
    plaintexts[5] = vaesdeclast(states[5], vxor(round_key, round_tweaks[5])); \
    plaintexts[6] = vaesdeclast(states[6], vxor(round_key, round_tweaks[6])); \
    plaintexts[7] = vaesdeclast(states[7], vxor(round_key, round_tweaks[7])); \
} while (0)

// ---------------------------------------------------------------------

#define aes_mix_columns_eight(states, zero) do {\
    states[0] = vaesdeclast(states[0], zero);\
    states[1] = vaesdeclast(states[1], zero);\
    states[2] = vaesdeclast(states[2], zero);\
    states[3] = vaesdeclast(states[3], zero);\
    states[4] = vaesdeclast(states[4], zero);\
    states[5] = vaesdeclast(states[5], zero);\
    states[6] = vaesdeclast(states[6], zero);\
    states[7] = vaesdeclast(states[7], zero);\
    states[0] = vaesenc(states[0], zero);\
    states[1] = vaesenc(states[1], zero);\
    states[2] = vaesenc(states[2], zero);\
    states[3] = vaesenc(states[3], zero);\
    states[4] = vaesenc(states[4], zero);\
    states[5] = vaesenc(states[5], zero);\
    states[6] = vaesenc(states[6], zero);\
    states[7] = vaesenc(states[7], zero);\
} while (0)

// ---------------------------------------------------------------------

#define aes_invert_mix_columns_eight(states, zero) do {\
    states[0] = vaesenclast(states[0], zero);\
    states[1] = vaesenclast(states[1], zero);\
    states[2] = vaesenclast(states[2], zero);\
    states[3] = vaesenclast(states[3], zero);\
    states[4] = vaesenclast(states[4], zero);\
    states[5] = vaesenclast(states[5], zero);\
    states[6] = vaesenclast(states[6], zero);\
    states[7] = vaesenclast(states[7], zero);\
    states[0] = vaesdec(states[0], zero);\
    states[1] = vaesdec(states[1], zero);\
    states[2] = vaesdec(states[2], zero);\
    states[3] = vaesdec(states[3], zero);\
    states[4] = vaesdec(states[4], zero);\
    states[5] = vaesdec(states[5], zero);\
    states[6] = vaesdec(states[6], zero);\
    states[7] = vaesdec(states[7], zero);\
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_generic_with_tmp(x, y, tmp, r1, r2, mask) do {\
    y = vxor(vand(mask, vshift_right(tmp, r1)), \
             vandnot(mask, vshift_left(x, r2)));\
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_four_sequence_base(x, tmp) do {\
    tmp = vxor(x[0], vshift_left(x[0], 2)); \
    lfsr_two_generic_with_tmp(x[0], x[1], tmp, 7, 1, set8(0x01)); \
    lfsr_two_generic_with_tmp(x[0], x[2], tmp, 6, 2, set8(0x03)); \
    lfsr_two_generic_with_tmp(x[0], x[3], tmp, 5, 3, set8(0x07)); \
    lfsr_two_generic_with_tmp(x[0], x[4], tmp, 4, 4, set8(0x0F)); \
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_six_sequence_base(x, tmp) do {\
    tmp = vxor(x[0], vshift_left(x[0], 2)); \
    lfsr_two_generic_with_tmp(x[0], x[1], tmp, 7, 1, set8(0x01)); \
    lfsr_two_generic_with_tmp(x[0], x[2], tmp, 6, 2, set8(0x03)); \
    lfsr_two_generic_with_tmp(x[0], x[3], tmp, 5, 3, set8(0x07)); \
    lfsr_two_generic_with_tmp(x[0], x[4], tmp, 4, 4, set8(0x0F)); \
    lfsr_two_generic_with_tmp(x[0], x[5], tmp, 3, 5, set8(0x1F)); \
    lfsr_two_generic_with_tmp(x[0], x[6], tmp, 2, 6, set8(0x3F)); \
} while (0)

// ---------------------------------------------------------------------

#define permute_base(x) do {\
    x[1] = permute(x[1], H_PERMUTATION_1);\
    x[2] = permute(x[2], H_PERMUTATION_2);\
    x[3] = permute(x[3], H_PERMUTATION_3);\
    x[4] = permute(x[4], H_PERMUTATION_4);\
    x[5] = permute(x[5], H_PERMUTATION_5);\
    x[6] = permute(x[6], H_PERMUTATION_6);\
    x[7] = permute(x[7], H_PERMUTATION_7);\
} while (0)

// ---------------------------------------------------------------------

#define update_invround_four_invmc(\
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i, j) do {\
    combine_avx_two(avx_round_tweaks, tweak_blocks, counters[j]); \
    permute_avx_two(avx_round_tweaks, i); \
    unpack_two(avx_round_tweaks, round_tweaks); \
    vinversemc_four(round_tweaks); \
    deoxys_dec_round_four(states, round_tweaks, round_keys[j]);\
} while (0)

// ---------------------------------------------------------------------

#define update_invround_four_invmc_no_permute(\
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i) do {\
    combine_avx_two(avx_round_tweaks, tweak_blocks, counters[i]); \
    unpack_two(avx_round_tweaks, round_tweaks); \
    vinversemc_four(round_tweaks); \
    deoxys_dec_round_four(states, round_tweaks, round_keys[i]);\
} while (0)

// ---------------------------------------------------------------------

#define update_invlastround_four_no_permute(\
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i) do {\
    combine_avx_two(avx_round_tweaks, tweak_blocks, counters[i]); \
    unpack_two(avx_round_tweaks, round_tweaks); \
    deoxys_declast_round_four(states, states, round_tweaks, round_keys[i]);\
} while (0)

// ---------------------------------------------------------------------

#define update_round_four(\
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i, j) do {\
    combine_avx_two(avx_round_tweaks, tweak_blocks, counters[j]); \
    permute_avx_two(avx_round_tweaks, i); \
    unpack_two(avx_round_tweaks, round_tweaks); \
    deoxys_enc_round_four(states, round_tweaks, round_keys[j]);\
} while (0)

// ---------------------------------------------------------------------

#define update_round_four_no_permute(\
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i) do {\
    combine_avx_two(avx_round_tweaks, tweak_blocks, counters[i]); \
    unpack_two(avx_round_tweaks, round_tweaks); \
    deoxys_enc_round_four(states, round_tweaks, round_keys[i]);\
} while (0)

// ---------------------------------------------------------------------
// For setup of eight tweaks
// ---------------------------------------------------------------------

#define pack_swap_eight(x1, x2, z) do {\
    z[0] = vswap128(x1[0], x2[0]);\
    z[1] = vswap128(x1[1], x2[1]);\
    z[2] = vswap128(x1[2], x2[2]);\
    z[3] = vswap128(x1[3], x2[3]);\
    z[4] = vswap128(x1[4], x2[4]);\
    z[5] = vswap128(x1[5], x2[5]);\
    z[6] = vswap128(x1[6], x2[6]);\
    z[7] = vswap128(x1[7], x2[7]);\
} while (0)

// ---------------------------------------------------------------------

#define pack_eight(x1, x2, z) do {\
    z[0] = vset128(x1[0], x2[0]);\
    z[1] = vset128(x1[1], x2[1]);\
    z[2] = vset128(x1[2], x2[2]);\
    z[3] = vset128(x1[3], x2[3]);\
    z[4] = vset128(x1[4], x2[4]);\
    z[5] = vset128(x1[5], x2[5]);\
    z[6] = vset128(x1[6], x2[6]);\
    z[7] = vset128(x1[7], x2[7]);\
} while (0)

// ---------------------------------------------------------------------

#define unpack_eight(z, y1, y2) do {\
    y1[0] = vget128(z[0], 0); \
    y2[0] = vget128(z[0], 1); \
    y1[1] = vget128(z[1], 0); \
    y2[1] = vget128(z[1], 1); \
    y1[2] = vget128(z[2], 0); \
    y2[2] = vget128(z[2], 1); \
    y1[3] = vget128(z[3], 0); \
    y2[3] = vget128(z[3], 1); \
    y1[4] = vget128(z[4], 0); \
    y2[4] = vget128(z[4], 1); \
    y1[5] = vget128(z[5], 0); \
    y2[5] = vget128(z[5], 1); \
    y1[6] = vget128(z[6], 0); \
    y2[6] = vget128(z[6], 1); \
    y1[7] = vget128(z[7], 0); \
    y2[7] = vget128(z[7], 1); \
} while (0)

// ---------------------------------------------------------------------

#define swap_halves_eight(x1, x2, z) do {\
    pack_swap_eight(x1, x2, z); \
    unpack_eight(z, x1, x2); \
} while (0)

// ---------------------------------------------------------------------

#define permute_avx_eight(z, i) do {\
    z[0] = permute_avx(z[0], VH_PERMUTATION_##i);\
    z[1] = permute_avx(z[1], VH_PERMUTATION_##i);\
    z[2] = permute_avx(z[2], VH_PERMUTATION_##i);\
    z[3] = permute_avx(z[3], VH_PERMUTATION_##i);\
    z[4] = permute_avx(z[4], VH_PERMUTATION_##i);\
    z[5] = permute_avx(z[5], VH_PERMUTATION_##i);\
    z[6] = permute_avx(z[6], VH_PERMUTATION_##i);\
    z[7] = permute_avx(z[7], VH_PERMUTATION_##i);\
} while (0)

// ---------------------------------------------------------------------

#define permute_avx_tweak_eight(x1, x2, z, i) do {\
    pack_eight(x1, x2, z); \
    permute_avx_eight(z, i); \
    unpack_eight(z, x1, x2); \
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_avx_generic_with_tmp(x, y, tmp, r1, r2, mask) do {\
    y = avx_xor(avx_and(mask, avx_shift_right(tmp, r1)), \
                avx_andnot(mask, avx_shift_left(x, r2)));\
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_avx_four_sequence(x, tmp) do {\
    tmp = avx_xor(x[0], avx_shift_left(x[0], 2)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 4], tmp, 7, 1, avx_set8(0x01)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 8], tmp, 6, 2, avx_set8(0x03)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[12], tmp, 5, 3, avx_set8(0x07)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[16], tmp, 4, 4, avx_set8(0x0F)); \
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_avx_six_sequence(x, tmp) do {\
    tmp = avx_xor(x[0], avx_shift_left(x[0], 2)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 4], tmp, 7, 1, avx_set8(0x01)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 8], tmp, 6, 2, avx_set8(0x03)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[12], tmp, 5, 3, avx_set8(0x07)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[16], tmp, 4, 4, avx_set8(0x0F)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[20], tmp, 3, 5, avx_set8(0x1F)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[24], tmp, 2, 6, avx_set8(0x3F)); \
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_avx_four_sequence_base(x, tmp) do {\
    tmp = avx_xor(x[0], avx_shift_left(x[0], 2)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[1], tmp, 7, 1, avx_set8(0x01)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[2], tmp, 6, 2, avx_set8(0x03)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[3], tmp, 5, 3, avx_set8(0x07)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[4], tmp, 4, 4, avx_set8(0x0F)); \
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_avx_six_sequence_base(x, tmp) do {\
    tmp = avx_xor(x[0], avx_shift_left(x[0], 2)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[1], tmp, 7, 1, avx_set8(0x01)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[2], tmp, 6, 2, avx_set8(0x03)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[3], tmp, 5, 3, avx_set8(0x07)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[4], tmp, 4, 4, avx_set8(0x0F)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[5], tmp, 3, 5, avx_set8(0x1F)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[6], tmp, 2, 6, avx_set8(0x3F)); \
} while (0)


/**
 * x is a 16-byte vector (x_15, x_14, ..., x_0), where all odd-indexed bytes
 * are a counter value: (0, ctr+7, 0, ctr+6, ..., 0, ctr).
 *
 * Consider a byte and its bits, e.g., x_0 = (76543210).
 * We define
 * y = (x xor (x << 2)) & 0xff = (76543210) xor (543210..)
 * z = y xor (y >> 6) = (76543210) xor (543210..) xor (......76) xor (......54)
 * w = (76543210) || z is then a 16-bit value.
 * Then, r times the LFSR2 application is given by a simple shift:
 * LFSR2^r(x) = (w >> (8-r)) & 0xFF.
 */
#define lfsr_two_avx_compute_tmp(x, z, w) do {\
    z = avx_and(x[0], AVX_MASK_ONLY_LOBYTES); \
    w = avx_xor(z, avx_shift_left(z, 2)); \
    w = avx_and(w, AVX_MASK_ONLY_LOBYTES); \
    w = avx_xor(w, avx_shift_right(w, 6)); \
    w = avx_or(avx_shift_bytes_left(z, 1), w); \
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_avx_eight_sequence_counters(x, z, tmp) do {\
    lfsr_two_avx_compute_tmp(x, z, tmp); \
    x[1] = avx_shift_right(tmp, 7); \
    x[2] = avx_shift_right(tmp, 6); \
    x[3] = avx_shift_right(tmp, 5); \
    x[4] = avx_shift_right(tmp, 4); \
    x[5] = avx_shift_right(tmp, 3); \
    x[6] = avx_shift_right(tmp, 2); \
    x[7] = avx_shift_right(tmp, 1); \
    x[8] = tmp; \
} while (0)

// ---------------------------------------------------------------------

#define permute_avx_four(z, i) do {\
    z[0] = permute_avx(z[0], VH_PERMUTATION_##i);\
    z[1] = permute_avx(z[1], VH_PERMUTATION_##i);\
    z[2] = permute_avx(z[2], VH_PERMUTATION_##i);\
    z[3] = permute_avx(z[3], VH_PERMUTATION_##i);\
} while (0)

// ---------------------------------------------------------------------

#define combine_avx_four(x, tweak_blocks, counter) do {\
    x[0] = avx_xor(tweak_blocks[0], avx_and(avx_shift_bytes_left(counter, 8), \
                                            AVX_BYTE_8_MASK)); \
    x[1] = avx_xor(tweak_blocks[1], avx_and(avx_shift_bytes_left(counter, 6), \
                                            AVX_BYTE_8_MASK)); \
    x[2] = avx_xor(tweak_blocks[2], avx_and(avx_shift_bytes_left(counter, 4), \
                                            AVX_BYTE_8_MASK)); \
    x[3] = avx_xor(tweak_blocks[3], avx_and(avx_shift_bytes_left(counter, 2), \
                                            AVX_BYTE_8_MASK)); \
} while (0)

// ---------------------------------------------------------------------

#define unpack_four(z, x) do {\
    x[0] = vget128(z[0], 0); \
    x[1] = vget128(z[0], 1); \
    x[2] = vget128(z[1], 0); \
    x[3] = vget128(z[1], 1); \
    x[4] = vget128(z[2], 0); \
    x[5] = vget128(z[2], 1); \
    x[6] = vget128(z[3], 0); \
    x[7] = vget128(z[3], 1); \
} while (0)

// ---------------------------------------------------------------------

#define init_counters(x, ctr) do {\
    x[0] = avx_add8(avx_setr8(ctr, 0, ctr, 0, ctr, 0, ctr, 0, \
                              ctr, 0, ctr, 0, ctr, 0, ctr, 0, \
                              ctr, 0, ctr, 0, ctr, 0, ctr, 0, \
                              ctr, 0, ctr, 0, ctr, 0, ctr, 0), \
                    avx_setr8(0, 0, 2, 0, 4, 0, 6, 0, \
                              8, 0, 10, 0, 12, 0, 14, 0, \
                              1, 0, 3, 0, 5, 0, 7, 0, 9, \
                              0, 11, 0, 13, 0, 15, 0)); \
} while (0)

// ---------------------------------------------------------------------

#define update_round_eight(\
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i, j) do {\
    combine_avx_four(avx_round_tweaks, tweak_blocks, counters[j]); \
    permute_avx_four(avx_round_tweaks, i); \
    unpack_four(avx_round_tweaks, round_tweaks); \
    deoxys_enc_round_eight(states, round_tweaks, round_keys[j]);\
} while (0)


// ---------------------------------------------------------------------

#define update_round_eight_no_permute( \
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i) do {\
    combine_avx_four(avx_round_tweaks, tweak_blocks, counters[i]); \
    unpack_four(avx_round_tweaks, round_tweaks); \
    deoxys_enc_round_eight(states, round_tweaks, round_keys[i]);\
} while (0)

// ---------------------------------------------------------------------

#define update_invround_eight( \
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i, j) do {\
    combine_avx_four(avx_round_tweaks, tweak_blocks, counters[j]); \
    permute_avx_four(avx_round_tweaks, i); \
    unpack_four(avx_round_tweaks, round_tweaks); \
    deoxys_dec_round_eight(states, round_tweaks, round_keys[j]);\
} while (0)

// ---------------------------------------------------------------------

#define update_invround_eight_invmc( \
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i, j) do {\
    combine_avx_four(avx_round_tweaks, tweak_blocks, counters[j]); \
    permute_avx_four(avx_round_tweaks, i); \
    unpack_four(avx_round_tweaks, round_tweaks); \
    aes_invert_mix_columns_eight(round_tweaks, vzero); \
    deoxys_dec_round_eight(states, round_tweaks, round_keys[j]);\
} while (0)

// ---------------------------------------------------------------------

#define update_invround_eight_invmc_no_permute( \
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i) do {\
    combine_avx_four(avx_round_tweaks, tweak_blocks, counters[i]); \
    unpack_four(avx_round_tweaks, round_tweaks); \
    aes_invert_mix_columns_eight(round_tweaks, vzero); \
    deoxys_dec_round_eight(states, round_tweaks, round_keys[i]);\
} while (0)

// ---------------------------------------------------------------------

#define update_invlastround_eight_no_permute( \
    avx_round_tweaks, tweak_blocks, counters, \
    round_tweaks, states, round_keys, i) do {\
    combine_avx_four(avx_round_tweaks, tweak_blocks, counters[i]); \
    unpack_four(avx_round_tweaks, round_tweaks); \
    deoxys_declast_round_eight(states, states, round_tweaks, round_keys[i]);\
} while (0)

// ---------------------------------------------------------------------
// For the middle step
// ---------------------------------------------------------------------

#define init_middle_counters(x, ctr) do {\
    x[0] = vadd8(setr8(ctr, 0, ctr, 0, ctr, 0, ctr, 0, \
                       ctr, 0, ctr, 0, ctr, 0, ctr, 0), \
                 setr8(0, 0, 1, 0, 2, 0, 3, 0, \
                       4, 0, 5, 0, 6, 0, 7, 0)); \
} while (0)

// ---------------------------------------------------------------------

/**
 * x is a 16-byte vector (x_15, x_14, ..., x_0), where all odd-indexed bytes
 * are a counter value: (0, ctr+7, 0, ctr+6, ..., 0, ctr).
 *
 * Consider a byte and its bits, e.g., x_0 = (76543210).
 * We define
 * y = (x xor (x << 2)) & 0xff = (76543210) xor (543210..)
 * z = y xor (y >> 6) = (76543210) xor (543210..) xor (......76) xor (......54)
 * w = (76543210) || z is then a 16-bit value.
 * Then, r times the LFSR2 application is given by a simple shift:
 * LFSR2^r(x) = (w >> (8-r)) & 0xFF.
 */
#define lfsr_two_compute_w(x, z, w) do {\
    z = vand(x[0], MASK_ONLY_LOBYTES); \
    w = vxor(z, vshift_left(z, 2)); \
    w = vand(w, MASK_ONLY_LOBYTES); \
    w = vxor(w, vshift_right(w, 6)); \
    w = vor(vshift_bytes_left(z, 1), w); \
} while (0)

// ---------------------------------------------------------------------

/**
 * Computes r times the LFSR2 application is given by a simple shift:
 * LFSR2^r(x) = (w >> (8-r)) & 0xFF.
 * Note: This does not yet perform the masking with & 0xFF.
 */
#define lfsr_two_eight_sequence_counters(x, z, tmp) do {\
    lfsr_two_compute_w(x, z, tmp); \
    x[1] = vshift_right(tmp, 7); \
    x[2] = vshift_right(tmp, 6); \
    x[3] = vshift_right(tmp, 5); \
    x[4] = vshift_right(tmp, 4); \
    x[5] = vshift_right(tmp, 3); \
    x[6] = vshift_right(tmp, 2); \
    x[7] = vshift_right(tmp, 1); \
    x[8] = tmp; \
} while (0)

// ---------------------------------------------------------------------

#define combine_eight(x, counter, permutation) do {\
    x[0] = vxor(x[0], permute(\
        vand(vshift_bytes_left(counter, 8), BYTE_8_MASK), permutation)); \
    x[1] = vxor(x[1], permute(\
        vand(vshift_bytes_left(counter, 6), BYTE_8_MASK), permutation)); \
    x[2] = vxor(x[2], permute(\
        vand(vshift_bytes_left(counter, 4), BYTE_8_MASK), permutation)); \
    x[3] = vxor(x[3], permute(\
        vand(vshift_bytes_left(counter, 2), BYTE_8_MASK), permutation)); \
    x[4] = vxor(x[4], permute(\
        vand(vshift_bytes_right(counter, 0), BYTE_8_MASK), permutation)); \
    x[5] = vxor(x[5], permute(\
        vand(vshift_bytes_right(counter, 2), BYTE_8_MASK), permutation)); \
    x[6] = vxor(x[6], permute(\
        vand(vshift_bytes_right(counter, 4), BYTE_8_MASK), permutation)); \
    x[7] = vxor(x[7], permute(\
        vand(vshift_bytes_right(counter, 6), BYTE_8_MASK), permutation)); \
} while (0)

// ---------------------------------------------------------------------

#define combine_eight_no_permute(x, counter) do {\
    x[0] = vxor(x[0], vand(vshift_bytes_left(counter, 8), BYTE_8_MASK)); \
    x[1] = vxor(x[1], vand(vshift_bytes_left(counter, 6), BYTE_8_MASK)); \
    x[2] = vxor(x[2], vand(vshift_bytes_left(counter, 4), BYTE_8_MASK)); \
    x[3] = vxor(x[3], vand(vshift_bytes_left(counter, 2), BYTE_8_MASK)); \
    x[4] = vxor(x[4], vand(vshift_bytes_right(counter, 0), BYTE_8_MASK)); \
    x[5] = vxor(x[5], vand(vshift_bytes_right(counter, 2), BYTE_8_MASK)); \
    x[6] = vxor(x[6], vand(vshift_bytes_right(counter, 4), BYTE_8_MASK)); \
    x[7] = vxor(x[7], vand(vshift_bytes_right(counter, 6), BYTE_8_MASK)); \
} while (0)

// ---------------------------------------------------------------------
// For setup of four tweaks
// ---------------------------------------------------------------------

#define lfsr_two_avx_four_sequence_two(x, tmp) do {\
    tmp = avx_xor(x[0], avx_shift_left(x[0], 2)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[2], tmp, 7, 1, avx_set8(0x01)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[4], tmp, 6, 2, avx_set8(0x03)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[6], tmp, 5, 3, avx_set8(0x07)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[8], tmp, 4, 4, avx_set8(0x0F)); \
} while (0)

// ---------------------------------------------------------------------

#define lfsr_two_avx_six_sequence_two(x, tmp) do {\
    tmp = avx_xor(x[0], avx_shift_left(x[0], 2)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 2], tmp, 7, 1, avx_set8(0x01)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 4], tmp, 6, 2, avx_set8(0x03)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 6], tmp, 5, 3, avx_set8(0x07)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[ 8], tmp, 4, 4, avx_set8(0x0F)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[10], tmp, 3, 5, avx_set8(0x1F)); \
    lfsr_two_avx_generic_with_tmp(x[0], x[12], tmp, 2, 6, avx_set8(0x3F)); \
} while (0)

// ---------------------------------------------------------------------

#define permute_avx_two(z, i) do {\
    z[0] = permute_avx(z[0], VH_PERMUTATION_##i);\
    z[1] = permute_avx(z[1], VH_PERMUTATION_##i);\
} while (0)

// ---------------------------------------------------------------------

#define permute_avx_all(z) do {\
    permute_avx_two((z +  2), 1); \
    permute_avx_two((z +  4), 2); \
    permute_avx_two((z +  6), 3); \
    permute_avx_two((z +  8), 4); \
    permute_avx_two((z + 10), 5); \
    permute_avx_two((z + 12), 6); \
    permute_avx_two((z + 14), 7); \
    permute_avx_two((z + 18), 1); \
    permute_avx_two((z + 20), 2); \
    permute_avx_two((z + 22), 3); \
    permute_avx_two((z + 24), 4); \
    permute_avx_two((z + 26), 5); \
    permute_avx_two((z + 28), 6); \
    permute_avx_two((z + 30), 7); \
} while (0)

// ---------------------------------------------------------------------

#define combine_avx_two(x, tweak_blocks, counter) do {\
    x[0] = avx_xor(tweak_blocks[0], avx_and(avx_shift_bytes_left(counter, 8), \
                                            AVX_BYTE_8_MASK)); \
    x[1] = avx_xor(tweak_blocks[1], avx_and(avx_shift_bytes_left(counter, 6), \
                                            AVX_BYTE_8_MASK)); \
} while (0)

// ---------------------------------------------------------------------

#define unpack_two(z, x) do {\
    x[0] = vget128(z[0], 0); \
    x[1] = vget128(z[0], 1); \
    x[2] = vget128(z[1], 0); \
    x[3] = vget128(z[1], 1); \
} while (0)

// ---------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------

static void add_round_constants(deoxys_bc_block_t* round_keys,
                                const size_t num_rounds) {
    for (size_t i = 0; i <= num_rounds; ++i) {
        const __m128i rcon = _mm_setr_epi8(1, 2, 4, 8,
            RCON[i], RCON[i], RCON[i], RCON[i], 0, 0, 0, 0, 0, 0, 0, 0);
        round_keys[i] = vxor(round_keys[i], rcon);
    }
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_key(deoxys_bc_128_384_ctx_t* ctx,
                                 const deoxys_bc_key_t key) {
    deoxys_bc_block_t* round_keys = ctx->round_keys;
    store(round_keys, (__m128i)key);

    for (size_t i = 0; i < DEOXYS_BC_128_384_NUM_ROUNDS; ++i) {
        lfsr_three(round_keys[i], round_keys[i+1]);
        round_keys[i+1] = permute_tweak(round_keys[i + 1]);
    }

    add_round_constants(round_keys, DEOXYS_BC_128_384_NUM_ROUNDS);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_decryption_key(deoxys_bc_128_384_ctx_t* ctx) {
    ctx->decryption_keys[0] = ctx->round_keys[0];

    for (size_t i = 1; i < DEOXYS_BC_128_384_NUM_ROUNDS; ++i) {
        ctx->decryption_keys[i] = vinversemc(ctx->round_keys[i]);
    }

    ctx->decryption_keys[DEOXYS_BC_128_384_NUM_ROUNDS]
        = ctx->round_keys[DEOXYS_BC_128_384_NUM_ROUNDS];
}

// ---------------------------------------------------------------------

static void deoxys_bc_128_384_setup_tweak(
    deoxys_bc_128_384_expanded_key_t round_tweaks,
    const uint8_t tweak_domain,
    const size_t tweak_counter,
    const deoxys_bc_block_t tweak_block) {
    deoxys_bc_block_t first_tweak = tweak_block;
    deoxys_bc_block_t second_tweak =
        set64(tweak_counter, (uint64_t)tweak_domain);
    deoxys_bc_block_t tmp;
    round_tweaks[0] = vxor(second_tweak, first_tweak);

    for (size_t i = 1; i < DEOXYS_BC_128_384_NUM_ROUND_KEYS; ++i) {
        lfsr_two(second_tweak, tmp);
        second_tweak = permute_tweak(tmp);
        first_tweak = permute_tweak(first_tweak);
        round_tweaks[i] = vxor(second_tweak, first_tweak);
    }
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_base_counters(deoxys_bc_128_384_ctx_t* ctx,
                                           const uint8_t tweak_domain,
                                           const size_t tweak_counter) {
    // ---------------------------------------------------------------------
    // LFSR2 on 16 rounds on the base counter and domain
    // ---------------------------------------------------------------------

    const uint64_t domain = (uint64_t)tweak_domain;
    const uint64_t base_counter = tweak_counter & 0xFFFFFFFFFFFFFF00L;

    ctx->base_counters[0] = set64(base_counter, domain);

    __m128i tmp;
    lfsr_two_six_sequence_base(ctx->base_counters, tmp);
    lfsr_two_six_sequence_base((ctx->base_counters + 6), tmp);
    lfsr_two_four_sequence_base((ctx->base_counters + 12), tmp);

    permute_base(ctx->base_counters);
    permute_base((ctx->base_counters + 8));

    for (size_t i = 0; i < DEOXYS_BC_128_384_NUM_ROUND_KEYS; ++i) {
        ctx->combined_round_keys[i] = vxor(ctx->round_keys[i],
                                           ctx->base_counters[i]);
    }

    ctx->combined_decryption_keys[0]
        =  vxor(ctx->decryption_keys[0],
                ctx->base_counters[0]);
    ctx->combined_decryption_keys[DEOXYS_BC_128_384_NUM_ROUNDS]
        = vxor(ctx->decryption_keys[DEOXYS_BC_128_384_NUM_ROUNDS],
               ctx->base_counters[DEOXYS_BC_128_384_NUM_ROUNDS]);

    for (size_t i = 1; i < DEOXYS_BC_128_384_NUM_ROUNDS; ++i) {
        tmp = vinversemc(ctx->base_counters[i]);
        ctx->combined_decryption_keys[i] = vxor(ctx->decryption_keys[i], tmp);
    }
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_setup_middle_base(deoxys_bc_128_384_ctx_t* ctx,
                                         const uint8_t tweak_domain,
                                         const size_t tweak_counter,
                                         const __m128i tweak_block) {
    // ---------------------------------------------------------------------
    // LFSR2 on 16 rounds on the base counter and domain
    // ---------------------------------------------------------------------

    const uint64_t domain = (uint64_t)tweak_domain;
    const uint64_t base_counter = tweak_counter & 0xFFFFFFFFFFFFFF00L;

    ctx->base_counters[0] = set64(base_counter, domain);

    __m128i tmp;
    lfsr_two_six_sequence_base(ctx->base_counters, tmp);
    lfsr_two_six_sequence_base((ctx->base_counters + 6), tmp);
    lfsr_two_four_sequence_base((ctx->base_counters + 12), tmp);

    // XOR T
    for (size_t i = 0; i < DEOXYS_BC_128_384_NUM_ROUND_KEYS; ++i) {
        ctx->base_counters[i] = vxor(ctx->base_counters[i], tweak_block);
    }

    // Permute base counters and tweak
    permute_base(ctx->base_counters);
    permute_base((ctx->base_counters + 8));

    for (size_t i = 0; i < DEOXYS_BC_128_384_NUM_ROUND_KEYS; ++i) {
        ctx->combined_round_keys[i] = vxor(ctx->round_keys[i],
                                           ctx->base_counters[i]);
    }
}

// ---------------------------------------------------------------------

static void deoxys_bc_128_384_setup_decryption_tweak(
    deoxys_bc_block_t* round_tweaks,
    const uint8_t tweak_domain,
    const size_t tweak_counter,
    const deoxys_bc_block_t tweak_block) {
    deoxys_bc_128_384_setup_tweak(round_tweaks,
                                  tweak_domain,
                                  tweak_counter,
                                  tweak_block);

    for (size_t i = 1; i < DEOXYS_BC_128_384_NUM_ROUNDS; ++i) {
        round_tweaks[i] = vinversemc(round_tweaks[i]);
    }
}

// ---------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------

static __m128i deoxys_bc_128_encrypt(const __m128i* round_keys,
                                     const __m128i* round_tweaks,
                                     const size_t num_rounds,
                                     deoxys_bc_block_t plaintext) {
    __m128i state = vxor3(plaintext, round_tweaks[0], round_keys[0]);

    for (size_t i = 1; i <= num_rounds; ++i) {
        state = vaesenc(state, vxor(round_keys[i], round_tweaks[i]));
    }

    return state;
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt(deoxys_bc_128_384_ctx_t* ctx,
                               const uint8_t tweak_domain,
                               const size_t tweak_counter,
                               const deoxys_bc_block_t tweak_block,
                               const deoxys_bc_block_t plaintext,
                               deoxys_bc_block_t* ciphertext) {
    deoxys_bc_128_384_setup_tweak(ctx->round_tweaks,
                                  tweak_domain,
                                  tweak_counter,
                                  tweak_block);

    *ciphertext = deoxys_bc_128_encrypt(ctx->round_keys,
                                        ctx->round_tweaks,
                                        DEOXYS_BC_128_384_NUM_ROUNDS,
                                        plaintext);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_four(deoxys_bc_128_384_ctx_t* ctx,
                                    const size_t tweak_counter,
                                    const __m256i tweak_blocks[2],
                                    deoxys_bc_block_t states[4]) {
    __m256i tmp, z;
    __m256i avx_round_tweaks[2];
    __m256i avx_counters[DEOXYS_BC_128_384_NUM_ROUND_KEYS];
    const uint8_t ctr = tweak_counter & 0xFF;

    init_counters(avx_counters, ctr);
    lfsr_two_avx_eight_sequence_counters(avx_counters, z, tmp);
    lfsr_two_avx_eight_sequence_counters((avx_counters + 8), z, tmp);

    combine_avx_two(avx_round_tweaks, tweak_blocks, avx_counters[0]);
    unpack_two(avx_round_tweaks, ctx->round_tweaks);

    vxor_four(ctx->round_tweaks, states, states);
    vxor_four_same(states, ctx->combined_round_keys[0]);

    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      1, 1);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      2, 2);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      3, 3);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      4, 4);

    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      5, 5);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      6, 6);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      7, 7);
    update_round_four_no_permute(avx_round_tweaks, tweak_blocks, avx_counters,
                                 ctx->round_tweaks, states,
                                 ctx->combined_round_keys, 8);

    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      1, 9);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      2, 10);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      3, 11);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      4, 12);

    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      5, 13);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      6, 14);
    update_round_four(avx_round_tweaks, tweak_blocks, avx_counters,
                      ctx->round_tweaks, states, ctx->combined_round_keys,
                      7, 15);
    update_round_four_no_permute(avx_round_tweaks, tweak_blocks, avx_counters,
                                 ctx->round_tweaks, states,
                                 ctx->combined_round_keys, 16);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_eight(deoxys_bc_128_384_ctx_t* ctx,
                                    const size_t tweak_counter,
                                    const __m256i tweak_blocks[4],
                                    deoxys_bc_block_t states[8]) {
    __m256i tmp, z;
    __m256i avx_round_tweaks[4];
    __m256i avx_counters[DEOXYS_BC_128_384_NUM_ROUND_KEYS];
    const uint8_t ctr = tweak_counter & 0xFF;

    init_counters(avx_counters, ctr);
    lfsr_two_avx_eight_sequence_counters(avx_counters, z, tmp);
    lfsr_two_avx_eight_sequence_counters((avx_counters + 8), z, tmp);

    combine_avx_four(avx_round_tweaks, tweak_blocks, avx_counters[0]);
    unpack_four(avx_round_tweaks,
                      ctx->round_tweaks);

    vxor_eight(ctx->round_tweaks, states, states);
    vxor_eight_same(states, ctx->combined_round_keys[0]);


    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       1, 1);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       2, 2);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       3, 3);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       4, 4);

    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       5, 5);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       6, 6);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       7, 7);
    update_round_eight_no_permute(avx_round_tweaks, tweak_blocks, avx_counters,
                                  ctx->round_tweaks, states,
                                  ctx->combined_round_keys, 8);

    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       1, 9);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       2, 10);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       3, 11);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       4, 12);

    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       5, 13);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       6, 14);
    update_round_eight(avx_round_tweaks, tweak_blocks, avx_counters,
                       ctx->round_tweaks, states, ctx->combined_round_keys,
                       7, 15);
    update_round_eight_no_permute(avx_round_tweaks, tweak_blocks, avx_counters,
                                  ctx->round_tweaks, states,
                                  ctx->combined_round_keys, 16);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_eight_eight(deoxys_bc_128_384_ctx_t* ctx,
                                           const size_t tweak_counter,
                                           const __m128i tweak_blocks[8],
                                           __m128i states[8]) {
    __m256i avx_tweak_blocks[4];
    avx_tweak_blocks[0] = vset128(tweak_blocks[0], tweak_blocks[1]);
    avx_tweak_blocks[1] = vset128(tweak_blocks[2], tweak_blocks[3]);
    avx_tweak_blocks[2] = vset128(tweak_blocks[4], tweak_blocks[5]);
    avx_tweak_blocks[3] = vset128(tweak_blocks[6], tweak_blocks[7]);

    deoxys_bc_128_384_encrypt_eight(ctx,
                                    tweak_counter,
                                    avx_tweak_blocks,
                                    states);
}

// ---------------------------------------------------------------------

#define aesenc_round_and_combine_counters(states, i, permutation) do { \
    vaesenc_round_eight(states, ctx->combined_round_keys[i]); \
    combine_eight(states, counters[i], permutation); \
} while (0)

// ---------------------------------------------------------------------

void deoxys_bc_128_384_encrypt_eight_one(deoxys_bc_128_384_ctx_t* ctx,
                                         const size_t tweak_counter,
                                         __m128i states[8]) {
    __m128i z;
    __m128i tmp;
    __m128i counters[DEOXYS_BC_128_384_NUM_ROUND_KEYS];
    const uint8_t ctr = tweak_counter & 0xFF;

    init_middle_counters(counters, ctr);
    lfsr_two_eight_sequence_counters(counters, z, tmp);
    lfsr_two_eight_sequence_counters((counters + 8), z, tmp);

    vxor_eight_same(states, ctx->combined_round_keys[0]);
    combine_eight_no_permute(states, counters[0]);

    aesenc_round_and_combine_counters(states, 1, H_PERMUTATION_1);
    aesenc_round_and_combine_counters(states, 2, H_PERMUTATION_2);
    aesenc_round_and_combine_counters(states, 3, H_PERMUTATION_3);
    aesenc_round_and_combine_counters(states, 4, H_PERMUTATION_4);
    aesenc_round_and_combine_counters(states, 5, H_PERMUTATION_5);
    aesenc_round_and_combine_counters(states, 6, H_PERMUTATION_6);
    aesenc_round_and_combine_counters(states, 7, H_PERMUTATION_7);

    vaesenc_round_eight(states, ctx->combined_round_keys[8]);
    combine_eight_no_permute(states, counters[8]);

    aesenc_round_and_combine_counters(states, 9, H_PERMUTATION_1);
    aesenc_round_and_combine_counters(states, 10, H_PERMUTATION_2);
    aesenc_round_and_combine_counters(states, 11, H_PERMUTATION_3);
    aesenc_round_and_combine_counters(states, 12, H_PERMUTATION_4);
    aesenc_round_and_combine_counters(states, 13, H_PERMUTATION_5);
    aesenc_round_and_combine_counters(states, 14, H_PERMUTATION_6);
    aesenc_round_and_combine_counters(states, 15, H_PERMUTATION_7);

    vaesenc_round_eight(states,
                        ctx->combined_round_keys[DEOXYS_BC_128_384_NUM_ROUNDS]);
    combine_eight_no_permute(states, counters[DEOXYS_BC_128_384_NUM_ROUNDS]);
}

// ---------------------------------------------------------------------
// Decryption
// ---------------------------------------------------------------------

static __m128i deoxys_bc_128_decrypt(const __m128i* round_keys,
                                     const __m128i* round_tweaks,
                                     const size_t num_rounds,
                                     deoxys_bc_block_t ciphertext) {
    __m128i state = vxor3(ciphertext,
                          round_tweaks[num_rounds],
                          round_keys[num_rounds]);

    state = vinversemc(state);

    for (size_t i = num_rounds - 1; i > 0; --i) {
        state = vaesdec(state, vxor(round_keys[i], round_tweaks[i]));
    }

    state = vaesdeclast(state, vxor(round_keys[0], round_tweaks[0]));
    return state;
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt(deoxys_bc_128_384_ctx_t* ctx,
                               const uint8_t tweak_domain,
                               const size_t tweak_counter,
                               const deoxys_bc_block_t tweak_block,
                               const deoxys_bc_block_t ciphertext,
                               deoxys_bc_block_t* plaintext) {
    deoxys_bc_128_384_setup_decryption_tweak(ctx->round_tweaks,
                                             tweak_domain,
                                             tweak_counter,
                                             tweak_block);

    *plaintext = deoxys_bc_128_decrypt(ctx->decryption_keys,
                                       ctx->round_tweaks,
                                       DEOXYS_BC_128_384_NUM_ROUNDS,
                                       ciphertext);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt_four(deoxys_bc_128_384_ctx_t* ctx,
                                    const size_t tweak_counter,
                                    __m256i tweak_blocks[2],
                                    deoxys_bc_block_t states[4]) {
    __m256i tmp, z;
    __m256i avx_round_tweaks[2];
    __m256i avx_counters[DEOXYS_BC_128_384_NUM_ROUND_KEYS];
    const uint8_t ctr = tweak_counter & 0xFF;

    init_counters(avx_counters, ctr);
    lfsr_two_avx_eight_sequence_counters(avx_counters, z, tmp);
    lfsr_two_avx_eight_sequence_counters((avx_counters + 8), z, tmp);

    combine_avx_two(avx_round_tweaks,
                    tweak_blocks,
                    avx_counters[DEOXYS_BC_128_384_NUM_ROUNDS]);
    unpack_two(avx_round_tweaks, ctx->round_tweaks);

    vxor_four(ctx->round_tweaks, states, states);
    vxor_four_same(states,
                   ctx->combined_decryption_keys[DEOXYS_BC_128_384_NUM_ROUNDS]);
    vinversemc_four(states);

    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 7, 15);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 6, 14);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 5, 13);

    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 4, 12);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 3, 11);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 2, 10);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 1, 9);

    update_invround_four_invmc_no_permute(avx_round_tweaks, tweak_blocks,
                            avx_counters, ctx->round_tweaks, states,
                            ctx->combined_decryption_keys, 8);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 7, 7);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 6, 6);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 5, 5);

    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 4, 4);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 3, 3);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 2, 2);
    update_invround_four_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                               ctx->round_tweaks, states,
                               ctx->combined_decryption_keys, 1, 1);

    update_invlastround_four_no_permute(avx_round_tweaks, tweak_blocks,
                                        avx_counters, ctx->round_tweaks, states,
                                        ctx->combined_decryption_keys, 0);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt_eight_eight(deoxys_bc_128_384_ctx_t* ctx,
                                           const size_t tweak_counter,
                                           const __m128i tweak_blocks[8],
                                           __m128i states[8]) {
    __m256i avx_tweak_blocks[4];
    avx_tweak_blocks[0] = vset128(tweak_blocks[0], tweak_blocks[1]);
    avx_tweak_blocks[1] = vset128(tweak_blocks[2], tweak_blocks[3]);
    avx_tweak_blocks[2] = vset128(tweak_blocks[4], tweak_blocks[5]);
    avx_tweak_blocks[3] = vset128(tweak_blocks[6], tweak_blocks[7]);

    deoxys_bc_128_384_decrypt_eight(ctx,
                                    tweak_counter,
                                    avx_tweak_blocks,
                                    states);
}

// ---------------------------------------------------------------------

void deoxys_bc_128_384_decrypt_eight(deoxys_bc_128_384_ctx_t* ctx,
                                     const size_t tweak_counter,
                                     __m256i tweak_blocks[4],
                                     deoxys_bc_block_t states[8]) {
    __m256i tmp, z;
    __m256i avx_round_tweaks[4];
    __m256i avx_counters[DEOXYS_BC_128_384_NUM_ROUND_KEYS];
    const uint8_t ctr = tweak_counter & 0xFF;

    init_counters(avx_counters, ctr);
    lfsr_two_avx_eight_sequence_counters(avx_counters, z, tmp);
    lfsr_two_avx_eight_sequence_counters((avx_counters + 8), z, tmp);

    combine_avx_four(avx_round_tweaks,
                     tweak_blocks,
                     avx_counters[DEOXYS_BC_128_384_NUM_ROUNDS]);
    unpack_four(avx_round_tweaks, ctx->round_tweaks);

    vxor_eight(ctx->round_tweaks, states, states);
    vxor_eight_same(states,
        ctx->combined_decryption_keys[DEOXYS_BC_128_384_NUM_ROUNDS]);
    aes_invert_mix_columns_eight(states, vzero);

    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 7, 15);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 6, 14);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 5, 13);

    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 4, 12);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 3, 11);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 2, 10);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 1, 9);

    update_invround_eight_invmc_no_permute(avx_round_tweaks, tweak_blocks,
                                           avx_counters, ctx->round_tweaks,
                                           states,
                                           ctx->combined_decryption_keys, 8);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 7, 7);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 6, 6);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 5, 5);

    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 4, 4);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 3, 3);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 2, 2);
    update_invround_eight_invmc(avx_round_tweaks, tweak_blocks, avx_counters,
                                ctx->round_tweaks, states,
                                ctx->combined_decryption_keys, 1, 1);

    update_invlastround_eight_no_permute(avx_round_tweaks, tweak_blocks,
                                         avx_counters, ctx->round_tweaks,
                                         states, ctx->combined_decryption_keys,
                                         0);
}
