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
#ifndef _GF_DOUBLING_TEST_CASE_CONTEXT_H_
#define _GF_DOUBLING_TEST_CASE_CONTEXT_H_

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
class GFDoublingTestCaseContext {
 public:
    GFDoublingTestCaseContext() = default;

    explicit
    GFDoublingTestCaseContext(const size_t num_input_bytes,
                                const size_t num_output_bytes,
                                const std::vector<uint8_t>& input,
                                const std::vector<uint8_t>& output) :
        num_input_bytes(num_input_bytes),
        num_output_bytes(num_output_bytes) {
        alloc_and_copy(&(this->input), input);
        alloc_and_copy(&(this->output), output);
    }

    // ----------------------------------------------------------

    ~GFDoublingTestCaseContext() {
        free_if_used(this->input, num_input_bytes);
        free_if_used(this->output, num_output_bytes);
    }

    // ----------------------------------------------------------

    size_t get_num_input_bytes() const { return num_input_bytes; }
    size_t get_num_output_bytes() const { return num_output_bytes; }

    uint8_t* input;
    uint8_t* output;

 private:
    size_t num_input_bytes = 0;
    size_t num_output_bytes = 0;
};

// ----------------------------------------------------------

#endif  // _GF_DOUBLING_TEST_CASE_CONTEXT_H_
