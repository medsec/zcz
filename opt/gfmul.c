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


// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>

#include "gfmul.h"
#include "utils-opt.h"

// ---------------------------------------------------------------------

#define accumulate_eight(x, y) { \
    x[0] = vxor(x[0], x[1]); \
    x[2] = vxor(x[2], x[3]); \
    x[4] = vxor(x[4], x[5]); \
    x[6] = vxor(x[6], x[7]); \
    x[0] = vxor(x[0], x[2]); \
    x[4] = vxor(x[4], x[6]); \
    y = vxor(x[0], x[4]); \
}

// ---------------------------------------------------------------------

__m128i gf_2_128_double_eight(__m128i hash, __m128i x[8]) {
    __m128i tmp[8];
    tmp[0] = vshift_right_64(hash, 56);
    tmp[1] = vshift_right_64(x[0], 57);
    tmp[2] = vshift_right_64(x[1], 58);
    tmp[3] = vshift_right_64(x[2], 59);
    tmp[4] = vshift_right_64(x[3], 60);
    tmp[5] = vshift_right_64(x[4], 61);
    tmp[6] = vshift_right_64(x[5], 62);
    tmp[7] = vshift_right_64(x[6], 63);

    __m128i sum;
    accumulate_eight(tmp, sum);

    // ---------------------------------------------------------------------
    // sum = sum_high || sum_low
    // We have to take sum_high * 135 and XOR it to our XOR sum to have the
    // Reduction term. The 0x01 indicates that sum_high is used.
    // ---------------------------------------------------------------------

    __m128i mod = clmul(sum, REDUCTION_POLYNOMIAL, 0x01);

    // Move sum_low to the upper 64-bit half
    __m128i sum_low = vshift_bytes_left(sum, 8);

    tmp[0] = vshift_left_64(hash, 8);
    tmp[1] = vshift_left_64(x[0], 7);
    tmp[2] = vshift_left_64(x[1], 6);
    tmp[3] = vshift_left_64(x[2], 5);
    tmp[4] = vshift_left_64(x[3], 4);
    tmp[5] = vshift_left_64(x[4], 3);
    tmp[6] = vshift_left_64(x[5], 2);
    tmp[7] = vshift_left_64(x[6], 1);

    accumulate_eight(tmp, sum);
    sum = vxor(sum, sum_low);
    sum = vxor(sum, mod);
    sum = vxor(sum, x[7]);
    return sum;
}

// ---------------------------------------------------------------------

__m128i gf_2_128_times_four_eight(__m128i hash, __m128i x[8]) {
    __m128i tmp[8];
    tmp[0] = vshift_right_64(hash, 48);
    tmp[1] = vshift_right_64(x[0], 50);
    tmp[2] = vshift_right_64(x[1], 52);
    tmp[3] = vshift_right_64(x[2], 54);
    tmp[4] = vshift_right_64(x[3], 56);
    tmp[5] = vshift_right_64(x[4], 58);
    tmp[6] = vshift_right_64(x[5], 60);
    tmp[7] = vshift_right_64(x[6], 62);

    __m128i sum;
    accumulate_eight(tmp, sum);

    // ---------------------------------------------------------------------
    // sum = sum_high || sum_low
    // We have to take sum_high * 135 and XOR it to our XOR sum to have the
    // Reduction term. The 0x01 indicates that sum_high is used.
    // ---------------------------------------------------------------------

    __m128i mod = clmul(sum, REDUCTION_POLYNOMIAL, 0x01);

    // Move sum_low to the upper 64-bit half
    __m128i sum_low = vshift_bytes_left(sum, 8);

    tmp[0] = vshift_left_64(hash, 16);
    tmp[1] = vshift_left_64(x[0], 14);
    tmp[2] = vshift_left_64(x[1], 12);
    tmp[3] = vshift_left_64(x[2], 10);
    tmp[4] = vshift_left_64(x[3], 8);
    tmp[5] = vshift_left_64(x[4], 6);
    tmp[6] = vshift_left_64(x[5], 4);
    tmp[7] = vshift_left_64(x[6], 2);

    accumulate_eight(tmp, sum);
    sum = vxor(sum, sum_low);
    sum = vxor(sum, mod);
    sum = vxor(sum, x[7]);
    return sum;
}
