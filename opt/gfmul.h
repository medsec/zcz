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
#ifndef _GFMUL_H_
#define _GFMUL_H_

// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>

// ---------------------------------------------------------------------

#define REDUCTION_POLYNOMIAL  set32(0, 0, 0, 135)

// ---------------------------------------------------------------------

#define gf_2_128_double(x, y, tmp) do {\
    tmp = _mm_srai_epi32(x, 31); \
    tmp = vand(tmp, set32(135, 1, 1, 1)); \
    tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2, 1, 0, 3)); \
    x = _mm_slli_epi32(x, 1); \
    y = vxor(x, tmp); \
} while (0)

// ---------------------------------------------------------------------

#define gf_2_128_times_four(x, y, tmp) do {\
    gf_2_128_double(x, y, tmp); \
    gf_2_128_double(y, y, tmp); \
} while (0)

// ---------------------------------------------------------------------

/**
 * Computes y = sum_{i = 0}^{8} x_i * 2^{8-i} in GF(2^{128}), using the 
 * reduction polynomial p(x) = x^{128} + x^7 + x^2 + x + 1.
 */
__m128i gf_2_128_double_eight(__m128i hash, __m128i x[8]);

/**
 * Computes y = sum_{i = 0}^{8} x_i * 2^{8-i} in GF(2^{128}), using the 
 * reduction polynomial p(x) = x^{128} + x^7 + x^2 + x + 1.
 */
__m128i gf_2_128_times_four_eight(__m128i hash, __m128i x[8]);

// ---------------------------------------------------------------------

#endif  // _GFMUL_H_
