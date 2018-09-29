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
#ifndef _ZCZ_TEST_CASE_CONTEXT_H_
#define _ZCZ_TEST_CASE_CONTEXT_H_

// ---------------------------------------------------------

#include <stdint.h>
#include <stdlib.h>

#include <string>
#include <vector>

#include "memutils.h"


// ----------------------------------------------------------

/**
 * Helper class that parses test case parameters from JSON files. So, our test
 * cases are cleaner and tests can be added easily.
 */
class ZCZTestCaseContext {
 public:
    ZCZTestCaseContext() = default;

    explicit
    ZCZTestCaseContext(const size_t num_plaintext_bytes,
                        const size_t num_ciphertext_bytes,
                        const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& ciphertext) :
        num_plaintext_bytes(num_plaintext_bytes),
        num_ciphertext_bytes(num_ciphertext_bytes) {
        alloc_and_copy(&(this->key), key);
        alloc_and_copy(&(this->plaintext), plaintext);
        alloc_and_copy(&(this->ciphertext), ciphertext);
    }

    // ----------------------------------------------------------

    ~ZCZTestCaseContext() {
        free(this->key);
        free_if_used(this->plaintext, num_plaintext_bytes);
        free_if_used(this->ciphertext, num_ciphertext_bytes);
    }

    // ----------------------------------------------------------

    size_t get_num_plaintext_bytes() const { return num_plaintext_bytes; }
    size_t get_num_ciphertext_bytes() const { return num_ciphertext_bytes; }

    uint8_t* key;
    uint8_t* plaintext;
    uint8_t* ciphertext;

 private:
    size_t num_plaintext_bytes = 0;
    size_t num_ciphertext_bytes = 0;
};

// ----------------------------------------------------------

#endif  // _ZCZ_TEST_CASE_CONTEXT_H_
