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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "utils.h"


// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

int assert_equal(const void* expected,
                  const void* actual,
                  const size_t num_bytes) {
    const int result = memcmp(expected, actual, num_bytes);
    return result == 0;
}

// ---------------------------------------------------------------------

void print_words_as_hex(const char* label,
                        const uint32_t s0,
                        const uint32_t s1,
                        const uint32_t s2,
                        const uint32_t s3) {
    printf("%s: ", label);
    printf("%08x", s0);
    printf("%08x", s1);
    printf("%08x", s2);
    printf("%08x\n", s3);
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

void to_le_array(uint8_t* target, const uint64_t source) {
    uint64_t v = source;

    for (size_t i = 0; i < 8; ++i) {
        target[i] = (uint8_t)(v) & 0xFF;
        v >>= 8;
    }
}

// ---------------------------------------------------------------------

void many_to_le_array(uint8_t* target,
                      const uint64_t* source,
                      const size_t num_words) {
    const size_t num_bytes_per_word = 8;

    for (size_t i = 0; i < num_words; i++) {
        to_le_array(target + i * num_bytes_per_word, source[i]);
    }
}

// ---------------------------------------------------------------------

void to_be_array(uint8_t* target, const uint64_t source) {
    for (size_t i = 0; i < 8; ++i) {
        target[i] =
          (uint8_t)(source >> (56 - (8 * i))) & 0xFF;
    }
}

// ---------------------------------------------------------------------

void many_to_be_array(uint8_t* target,
                      const uint64_t* source,
                      const size_t num_words) {
    const size_t num_bytes_per_word = 8;

    for (size_t i = 0; i < num_words; i++) {
        to_be_array(target + i * num_bytes_per_word, source[i]);
    }
}

// ---------------------------------------------------------------------

void to_array_partial(uint8_t* target,
                      const uint64_t* source,
                      const size_t num_bytes) {
    const size_t num_bytes_per_word = 8;
    const size_t num_full_words = num_bytes / num_bytes_per_word;

    for (size_t i = 0; i < num_full_words; i++) {
        to_be_array(target + i * num_bytes_per_word, source[i]);
    }

    const size_t num_remaining_bytes = num_bytes % num_bytes_per_word;
    const size_t start_byte = num_full_words * num_bytes_per_word;

    for (size_t i = 0; i < num_remaining_bytes; i++) {
        target[start_byte + i] =
                (uint8_t)(source[num_full_words] >> (56 - (8 * i))) & 0xFF;
    }
}

// ---------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------

int compare(const uint8_t* a,
            const uint8_t* b,
            const size_t num_bytes) {
    uint8_t result = 0;

    for (size_t i = 0; i < num_bytes; i++) {
        result |= a[i] ^ b[i];
    }

    return result;
}

// ---------------------------------------------------------------------

void gf_double(uint8_t* out,
               const uint8_t* in,
               const size_t num_bytes) {
    assert(num_bytes >= 1);

    for (size_t i = 1; i < num_bytes; ++i) {
        out[i] = ((in[i] << 1) & 0xfe)
            | ((in[i-1] >> 7) & 0x01);
    }

    const uint8_t msb = (in[num_bytes-1] >> 7) & 0x01;
    out[0] = (in[0] << 1) & 0xfe;
    out[0] ^= msb * 0x87;
}

// ---------------------------------------------------------------------

// void gf_double(uint8_t* out,
//                const uint8_t* in,
//                const size_t num_bytes) {
//     assert(num_bytes >= 1);

//     for (size_t i = 0; i < num_bytes-1; ++i) {
//         out[i] = ((in[i] << 1) & 0xfe)
//             | ((in[i+1] >> 7) & 0x01);
//     }

//     const uint8_t msb = (in[0] >> 7) & 0x01;
//     out[num_bytes-1] = (in[num_bytes-1] << 1) & 0xfe;
//     out[num_bytes-1] ^= msb * 0x87;
// }

// ---------------------------------------------------------------------

void gf_times_four(uint8_t* out,
                   const uint8_t* in,
                   const size_t num_bytes) {
    assert(num_bytes >= 2);

    for (size_t i = 1; i < num_bytes; ++i) {
        out[i] = ((in[i] << 2) & 0xfc)
            | ((in[i-1] >> 6) & 0x03);
    }

    const uint8_t msb = (in[num_bytes-1] >> 7) & 0x01;
    const uint8_t msb2 = (in[num_bytes-1] >> 6) & 0x01;

    out[0] = (in[0] << 2) & 0xfc;
    out[0] ^= msb2 * 0x87;
    out[0] ^= msb * 0x0e;
    out[1] ^= msb * 0x01;
}

// ---------------------------------------------------------------------

// void gf_times_four(uint8_t* out,
//                    const uint8_t* in,
//                    const size_t num_bytes) {
//     assert(num_bytes >= 2);

//     for (size_t i = 0; i < num_bytes-1; ++i) {
//         out[i] = ((in[i] << 2) & 0xfc)
//             | ((in[i+1] >> 6) & 0x03);
//     }

//     const uint8_t msb = (in[0] >> 7) & 0x01;
//     const uint8_t msb2 = (in[0] >> 6) & 0x01;

//     out[num_bytes-1] = (in[num_bytes-1] << 2) & 0xfc;
//     out[num_bytes-1] = msb2 * 0x87;
//     out[num_bytes-1] = msb * 0x0e;
//     out[num_bytes-2] = msb * 0x01;
// }

// ---------------------------------------------------------------------

void vand(uint8_t* out,
          const uint8_t* a,
          const uint8_t* b,
          const size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; ++i) {
        out[i] = a[i] & b[i];
    }
}

// ---------------------------------------------------------------------

void vor(uint8_t* out,
         const uint8_t* a,
         const uint8_t* b,
         const size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; ++i) {
        out[i] = a[i] | b[i];
    }
}

// ---------------------------------------------------------------------

void vxor(uint8_t* out,
          const uint8_t* a,
          const uint8_t* b,
          const size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; ++i) {
        out[i] = a[i] ^ b[i];
    }
}

// ---------------------------------------------------------------------

void zeroize(uint8_t* x, const size_t num_bytes) {
    memset(x, 0x00, num_bytes);
}

// ---------------------------------------------------------------------

void revert_bytes(uint8_t* array, const size_t num_bytes) {
    uint8_t tmp;

    for (size_t i = 0; i < num_bytes; ++i) {
        tmp = array[i];
        array[i] = array[num_bytes - 1 - i];
        array[num_bytes - 1 - i] = tmp;
    }
}

// ---------------------------------------------------------------------
