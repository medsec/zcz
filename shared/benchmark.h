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
#ifndef _BENCHMARK_H_
#define _BENCHMARK_H_

// ---------------------------------------------------------------------

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

// ---------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------

#define _Is_X86_            1
#define HI_RES_CLK_OK
#define TIMER_SAMPLE_CNT    (91 * 100)
#define MAX_BUFFER_LEN      65536

// ---------------------------------------------------------------------

#if __GNUC__
    #define ALIGN(n)      __attribute__ ((aligned(n)))
#elif _MSC_VER
    #define ALIGN(n)      __declspec(align(n))
#else
    #define ALIGN(n)
#endif

// ---------------------------------------------------------------------

int compare_doubles(const void *aPtr, const void *bPtr);

// ---------------------------------------------------------------------

uint64_t get_time();

// ---------------------------------------------------------------------

uint64_t calibrate_timer();

// ---------------------------------------------------------------------

int benchmark(const size_t num_iterations);

// ---------------------------------------------------------------------

#endif  // _BENCHMARK_H_
