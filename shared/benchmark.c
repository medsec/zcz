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
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "benchmark.h"

// ---------------------------------------------------------------------

int compare_doubles(const void *aPtr, const void *bPtr) {
    const double a = *((const double*) aPtr);
    const double b = *((const double*) bPtr);

    if (a > b) {
        return  1;
    }

    if (a < b) {
        return -1;
    }

    return 0;
}

// ---------------------------------------------------------------------

uint64_t get_time() {
    uint64_t x[2];
    __asm__ volatile("rdtsc" : "=a"(x[0]), "=d"(x[1]));
    return x[0];
}

// ---------------------------------------------------------------------

/**
 * Measures the overhead for measuring time.
 */
uint64_t calibrate_timer() {
    // big number to start
    uint64_t min_timing_distance = 0xFFFFFFFFL;
    uint64_t t0, t1;
    int i;

    for (i = 0; i < TIMER_SAMPLE_CNT; ++i) {
        t0 = get_time();
        t1 = get_time();

        if (min_timing_distance > t1 - t0) {
            min_timing_distance = t1 - t0;
        }
    }

    return min_timing_distance;
}
