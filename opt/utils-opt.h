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

#ifndef _UTILS_OPT_H_
#define _UTILS_OPT_H_

// ---------------------------------------------------------------------

#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <wmmintrin.h>
#include <stdint.h>

// ---------------------------------------------------------------------
// Load, Store, Helpers
// ---------------------------------------------------------------------

#define loadu(p)            _mm_loadu_si128((__m128i*)p)
#define load(p)             _mm_load_si128((__m128i*)p)
#define storeu(p, x)        _mm_storeu_si128((__m128i*)p, x)
#define store(p, x)         _mm_store_si128((__m128i*)p, x)

#define avx_loadu(p)        _mm256_loadu_si256((__m256i*)p)
#define avx_load(p)         _mm256_load_si256((__m256i*)p)
#define avx_storeu(p, x)    _mm256_storeu_si256((__m256i*)p, x)
#define avx_store(p, x)     _mm256_store_si256((__m256i*)p, x)

// _mm_set_epi8(15, 14, ... 1, 0)  = (15, 14, ...,  1,  0)
// _mm_setr_epi8(15, 14, ... 1, 0) = ( 0,  1, ..., 14, 15)

#define vzero               _mm_setzero_si128()
#define set8(x)             _mm_set1_epi8(x)

// x0 = lowest byte, x15 = highest byte
#define setr8(x0, x1, x2, x3, x4, x5, x6, x7, \
              x8, x9, x10, x11, x12, x13, x14, x15) \
    _mm_setr_epi8(x0, x1, x2, x3, x4, x5, x6, x7, \
                  x8, x9, x10, x11, x12, x13, x14, x15)
#define vone                setr8(0, 0, 0, 0, 0, 0, 0, 0, \
                                  0, 0, 0, 0, 0, 0, 0, 1)
#define veight              setr8(0, 0, 0, 0, 0, 0, 0, 0, \
                                  0, 0, 0, 0, 0, 0, 0, 8)
#define vseight             setr8(0, 0, 0, 0, 0, 0, 0, 0, \
                                  8, 0, 0, 0, 0, 0, 0, 0)
#define PERM_MASK           setr8(0, 1, 2, 3, 4, 5, 6, 7, \
                                  15, 14, 13, 12, 11, 10, 9, 8)

#define vadd8(x, y)         _mm_add_epi8(x, y)
#define vadd(x, y)          _mm_add_epi64(x, y)
#define vand(x, y)          _mm_and_si128(x, y)
#define vandnot(x, y)       _mm_andnot_si128(x, y)
#define vor(x, y)           _mm_or_si128(x, y)
#define vxor(x, y)          _mm_xor_si128(x, y)
#define vxor3(x, y, z)      _mm_xor_si128(x, _mm_xor_si128(y, z))
#define set32(x3, x2, x1, x0) _mm_set_epi32(x3, x2, x1, x0)
#define set64(hi, lo)       _mm_set_epi64((__m64)(hi), (__m64)(lo))
#define vget64(x, i)        _mm_extract_epi64(x, i)
#define vget128(y, i)       _mm256_extracti128_si256(y, i)
#define vset128(x1, x2)     _mm256_set_epi64x(vget64(x2, 1), \
                                              vget64(x2, 0), \
                                              vget64(x1, 1), \
                                              vget64(x1, 0))
#define vswap128(x1, x2)    _mm256_set_epi64x(vget64(x2, 0), \
                                              vget64(x2, 1), \
                                              vget64(x1, 0), \
                                              vget64(x1, 1))

#define vshift_bytes_left(x, r)      _mm_bslli_si128(x, r)
#define vshift_bytes_right(x, r)     _mm_bsrli_si128(x, r)
#define vshift_left(x, r)            _mm_slli_epi16(x, r)
#define vshift_right(x, r)           _mm_srli_epi16(x, r)
#define vshift_left_32(x, r)         _mm_slli_epi32(x, r)
#define vshift_right_32(x, r)        _mm_srli_epi32(x, r)
#define vshift_left_64(x, r)         _mm_slli_epi64(x, r)
#define vshift_right_64(x, r)        _mm_srli_epi64(x, r)
#define vcompare(x, y)              !_mm_test_all_zeros(vxor(x, y), set8(0xff))

// ---------------------------------------------------------------------
// AVX-specific
// ---------------------------------------------------------------------

#define avx_add8(x, y)               _mm256_add_epi8(x, y)
#define avx_and(x, y)                _mm256_and_si256(x, y)
#define avx_andnot(x, y)             _mm256_andnot_si256(x, y)
#define avx_or(x, y)                 _mm256_or_si256(x, y)
#define avx_xor(x, y)                _mm256_xor_si256(x, y)
#define avx_xor3(x, y, z)            _mm256_xor_si256(x, _mm256_xor_si256(y, z))
#define avx_shift_bytes_right(x, r)  _mm256_bsrli_epi128(x, r)
#define avx_shift_bytes_left(x, r)   _mm256_bslli_epi128(x, r)
#define avx_shift_left(x, r)         _mm256_slli_epi16(x, r)
#define avx_shift_right(x, r)        _mm256_srli_epi16(x, r)

#define avx_set64(x3, x2, x1, x0)    _mm256_set_epi64x(x3, x2, x1, x0)
#define avx_set8(x)                  _mm256_set1_epi8(x)
#define avx_setr8(x0, x1, x2, x3, x4, x5, x6, x7, \
                  x8, x9, x10, x11, x12, x13, x14, x15, \
                  x16, x17, x18, x19, x20, x21, x22, x23, \
                  x24, x25, x26, x27, x28, x29, x30, x31)\
    _mm256_setr_epi8(x0, x1, x2, x3, x4, x5, x6, x7, \
                     x8, x9, x10, x11, x12, x13, x14, x15, \
                     x16, x17, x18, x19, x20, x21, x22, x23, \
                     x24, x25, x26, x27, x28, x29, x30, x31)

// ---------------------------------------------------------------------

#define avx_load_two(p, x) do {\
    p[0] = avx_loadu(x);\
    p[1] = avx_loadu(x+1);\
} while (0)

// ---------------------------------------------------------------------

#define avx_store_two(p, x) do {\
    avx_storeu(p, x[0]);\
    avx_storeu(p+1, x[1]);\
} while (0)

// ---------------------------------------------------------------------

#define avx_load_four(p, x) do {\
    p[0] = avx_loadu(x);\
    p[1] = avx_loadu(x+1);\
    p[2] = avx_loadu(x+2);\
    p[3] = avx_loadu(x+3);\
} while (0)

// ---------------------------------------------------------------------

#define avx_store_four(p, x) do {\
    avx_storeu(p, x[0]);\
    avx_storeu(p+1, x[1]);\
    avx_storeu(p+2, x[2]);\
    avx_storeu(p+3, x[3]);\
} while (0)

// ---------------------------------------------------------------------
// Multiple blocks
// ---------------------------------------------------------------------

#define load_four(p, x) do {\
    p[0] = loadu(x);\
    p[1] = loadu(x+1);\
    p[2] = loadu(x+2);\
    p[3] = loadu(x+3);\
} while (0)

// ---------------------------------------------------------------------

#define store_four(p, x) do {\
    storeu(p, x[0]);\
    storeu(p+1, x[1]);\
    storeu(p+2, x[2]);\
    storeu(p+3, x[3]);\
} while (0)

// ---------------------------------------------------------------------

#define load_eight(p, x) do {\
    p[0] = loadu(x);\
    p[1] = loadu(x+1);\
    p[2] = loadu(x+2);\
    p[3] = loadu(x+3);\
    p[4] = loadu(x+4);\
    p[5] = loadu(x+5);\
    p[6] = loadu(x+6);\
    p[7] = loadu(x+7);\
} while (0)

// ---------------------------------------------------------------------

#define store_eight(p, x) do {\
    storeu(p, x[0]);\
    storeu(p+1, x[1]);\
    storeu(p+2, x[2]);\
    storeu(p+3, x[3]);\
    storeu(p+4, x[4]);\
    storeu(p+5, x[5]);\
    storeu(p+6, x[6]);\
    storeu(p+7, x[7]);\
} while (0)

// ---------------------------------------------------------------------

#define gf_double(x, y, tmp) do {\
    tmp = _mm_srai_epi32(x, 31); \
    tmp = vand(tmp, _mm_set_epi32(135, 1, 1, 1)); \
    tmp = _mm_shuffle_epi32(tmp, _MM_SHUFFLE(2, 1, 0, 3)); \
    x = _mm_slli_epi32(x, 1); \
    y = vxor(x, tmp); \
} while (0)

// ---------------------------------------------------------------------

#define gf_times_four(x, y, tmp) do { \
    gf_double(x, y, tmp); \
    gf_double(y, y, tmp); \
} while (0)

// ---------------------------------------------------------------------
// AES
// ---------------------------------------------------------------------

#define vaesenc(x, y)       _mm_aesenc_si128(x, y)
#define vaesenclast(x, y)   _mm_aesenclast_si128(x, y)
#define vaesdec(x, y)       _mm_aesdec_si128(x, y)
#define vaesdeclast(x, y)   _mm_aesdeclast_si128(x, y)
#define vinversemc(x)       _mm_aesimc_si128(x)
#define clmul(x, y, mask)   _mm_clmulepi64_si128(x, y, mask)

// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

__m128i load_partial(const void *p, size_t n);

void store_partial(const void *p, __m128i x, size_t n);

void print_hex_128(const char* label, const __m128i value);

void print_hex_256(const char* label, const __m256i value);

void print_hex(const char* label,
               const uint8_t* array,
               const size_t num_bytes);

// ---------------------------------------------------------------------

#endif  // _UTILS_OPT_H_
