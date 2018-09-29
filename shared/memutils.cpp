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
#include <stdlib.h>
#include <vector>

#include "memutils.h"


// ----------------------------------------------------------

void alloc_and_copy(uint8_t** target,
                    const std::vector<uint8_t>& source) {
    if (source.size() == 0) {
        return;
    }

    *target = (uint8_t*)malloc(source.size());

    for (size_t i = 0; i < source.size(); ++i) {
        (*target)[i] = source[i];
    }
}

// ----------------------------------------------------------

void free_if_used(uint8_t* target, const size_t size) {
    if (size > 0) {
        free(target);
    }
}
