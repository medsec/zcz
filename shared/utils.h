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

#ifndef _UTILS_H_
#define _UTILS_H_

// ---------------------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>


// ---------------------------------------------------------------------
// API
// ---------------------------------------------------------------------

void print_words_as_hex(const char* label,
                        const uint32_t s0,
                        const uint32_t s1,
                        const uint32_t s2,
                        const uint32_t s3);

// ---------------------------------------------------------------------

void print_hex(const char* label,
               const uint8_t* array,
               const size_t num_bytes);

// ---------------------------------------------------------------------

void to_le_array(uint8_t* target, const uint64_t source);

// ---------------------------------------------------------------------

void many_to_le_array(uint8_t* target,
                      const uint64_t* source,
                      const size_t num_words);

// ---------------------------------------------------------------------

void to_be_array(uint8_t* target, const uint64_t source);

// ---------------------------------------------------------------------

void many_to_be_array(uint8_t* target,
                      const uint64_t* source,
                      const size_t num_words);

// ---------------------------------------------------------------------

void to_array_partial(uint8_t* target,
                      const uint64_t* source,
                      const size_t num_bytes);

// ---------------------------------------------------------------------

int compare(const uint8_t* a,
            const uint8_t* b,
            const size_t num_bytes);

// ---------------------------------------------------------------------

void gf_double(uint8_t* out,
               const uint8_t* in,
               const size_t num_bytes);

// ---------------------------------------------------------------------

void gf_times_four(uint8_t* out,
                   const uint8_t* in,
                   const size_t num_bytes);

// ---------------------------------------------------------------------

void vand(uint8_t* out,
          const uint8_t* a,
          const uint8_t* b,
          const size_t num_bytes);

// ---------------------------------------------------------------------

void vor(uint8_t* out,
         const uint8_t* a,
         const uint8_t* b,
         const size_t num_bytes);

// ---------------------------------------------------------------------

void vxor(uint8_t* out,
          const uint8_t* a,
          const uint8_t* b,
          const size_t num_bytes);

// ---------------------------------------------------------------------

void zeroize(uint8_t* x, const size_t num_bytes);

// ---------------------------------------------------------------------

void revert_bytes(uint8_t* array, const size_t num_bytes);

// ---------------------------------------------------------------------

#endif  // _UTILS_H_
