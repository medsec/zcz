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

#include <stdio.h>

#include "utils-opt.h"


// ---------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------

__m128i load_partial(const void *p, size_t n) {
    if (n == 0) {
        return vzero;
    } else if (n % 16 == 0) {
        return _mm_loadu_si128((__m128i*)p);
    } else {
        __m128i tmp;
        size_t i;

        for (i = 0; i < n; ++i) {
            ((char*)&tmp)[i] = ((char*)p)[i];
        }

        return tmp;
    }
}

// ---------------------------------------------------------------------

void store_partial(const void *p, __m128i x, size_t n) {
    if (n == 0) {
        return;
    } else if (n >= 16) {
        storeu(p, x);
    } else {
        size_t i;
        uint8_t* p_ = (uint8_t*)p;
        uint8_t* x_ = (uint8_t*)&x;

        for (i = 0; i < n; ++i) {
            p_[i] = x_[i];
        }
    }
}

// ---------------------------------------------------------------------

void print_hex(const char* label,
               const uint8_t* array,
               const size_t num_bytes) {
    printf("%s: ", label);

    for (size_t i = 0; i < num_bytes; i++) {
        printf("%02x", array[i]);
    }

    puts("");
}

// ---------------------------------------------------------------------

void print_hex_128(const char* label, const __m128i value) {
    uint8_t array[16];
    store(array, value);
    print_hex(label, array, 16);
}

// ---------------------------------------------------------------------

void print_hex_256(const char* label, const __m256i value) {
    uint8_t array[32];
    avx_store(array, value);
    print_hex(label, array, 32);
}

// ---------------------------------------------------------------------
