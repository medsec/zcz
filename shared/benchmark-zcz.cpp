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

extern "C" {
    #include "benchmark.h"
    #include "utils-opt.h"
    #include "zcz.h"
}


// ---------------------------------------------------------------------

static const size_t NUM_ITERATIONS = 10000;
static const size_t NUM_MESSAGE_LENGTHS = 12;
static const size_t MAX_NUM_BYTES_CONTINUOUS = 2048;
static const size_t MESSAGE_LENGTHS[NUM_MESSAGE_LENGTHS] = {
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
};
static const size_t NUM_BYTES_PER_INTERVAL = 32;

// ---------------------------------------------------------------------

typedef struct {
    ALIGN(16)
    uint8_t key[ZCZ_NUM_KEY_BYTES];
    zcz_ctx_t ctx;
    ALIGN(16)
    uint8_t* plaintext;
    uint8_t* ciphertext;
    size_t num_bytes;
    size_t max_num_bytes;
} benchmark_ctx_t;

// ---------------------------------------------------------------------

static void fill(uint8_t* array, const size_t num_bytes) {
    for (size_t i = 0; i < num_bytes; ++i) {
        array[i] = i & 0xFF;
    }
}

// ---------------------------------------------------------------------

static void initialize(benchmark_ctx_t* context, const size_t max_num_bytes) {
    fill(context->key, ZCZ_NUM_KEY_BYTES);
    zcz_keysetup(&(context->ctx), context->key);

    context->plaintext = (uint8_t*)malloc(max_num_bytes);
    context->ciphertext = (uint8_t*)malloc(max_num_bytes);

    fill(context->plaintext, max_num_bytes);
}

// ---------------------------------------------------------------------

static void finalize(benchmark_ctx_t* context) {
    free(context->plaintext);
    free(context->ciphertext);
}

// ---------------------------------------------------------------------

static void run_operation(benchmark_ctx_t* context,
                          const size_t num_plaintext_bytes) {
    uint8_t* plaintext = context->plaintext;
    uint8_t* ciphertext = context->ciphertext;

    zcz_ctx_t* ctx = &(context->ctx);
    zcz_encrypt(ctx, plaintext, num_plaintext_bytes, ciphertext);
}

// ---------------------------------------------------------------------

static int benchmark() {
    // ---------------------------------------------------------------------
    // Initialization
    // ---------------------------------------------------------------------

    size_t num_plaintext_bytes;
    benchmark_ctx_t ctx;
    initialize(&ctx, MESSAGE_LENGTHS[NUM_MESSAGE_LENGTHS-1]);

    // ---------------------------------------------------------------------
    // Warm up
    // ---------------------------------------------------------------------

    const uint64_t calibration = calibrate_timer();
    uint64_t t0;
    uint64_t t1;

    puts("#Bytes cpb");

    for (size_t j = 0; j < NUM_MESSAGE_LENGTHS; ++j) {
        for (size_t i = 0; i < NUM_ITERATIONS / 4; ++i) {
            num_plaintext_bytes = MESSAGE_LENGTHS[j];
            run_operation(&ctx, num_plaintext_bytes);
        }
    }

    double timings[NUM_ITERATIONS];
    const uint32_t median = NUM_ITERATIONS / 2;

    const size_t min_num_bytes = MESSAGE_LENGTHS[0];

    // ---------------------------------------------------------------------
    // Benchmark
    // ---------------------------------------------------------------------

    for (size_t j = min_num_bytes;
        j <= MAX_NUM_BYTES_CONTINUOUS;
        j += NUM_BYTES_PER_INTERVAL) {
        num_plaintext_bytes = j;
        t0 = get_time();
        t1 = get_time();

        for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
            t0 = get_time();
            run_operation(&ctx, num_plaintext_bytes);
            t1 = get_time();
            timings[i] = (double)(t1 - t0 - calibration) / num_plaintext_bytes;
        }

        // ---------------------------------------------------------------------
        // Sort the measurements and print the median
        // ---------------------------------------------------------------------

        qsort(timings, NUM_ITERATIONS, sizeof(double), compare_doubles);
        printf("%5zu %4.2lf \n", num_plaintext_bytes, timings[median]);
    }

    // ---------------------------------------------------------------------
    // Benchmark
    // ---------------------------------------------------------------------

    for (size_t j = 7; j < NUM_MESSAGE_LENGTHS; j++) {
        num_plaintext_bytes = MESSAGE_LENGTHS[j];

        t0 = get_time();
        t1 = get_time();

        for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
            t0 = get_time();
            run_operation(&ctx, num_plaintext_bytes);
            t1 = get_time();
            timings[i] = (double)(t1 - t0 - calibration) / num_plaintext_bytes;
        }

        // ---------------------------------------------------------------------
        // Sort the measurements and print the median
        // ---------------------------------------------------------------------

        qsort(timings, NUM_ITERATIONS, sizeof(double), compare_doubles);
        printf("%5zu %4.2lf \n", num_plaintext_bytes, timings[median]);
    }

    // ---------------------------------------------------------------------
    // Finalize
    // ---------------------------------------------------------------------

    finalize(&ctx);
    return 0;
}

// ---------------------------------------------------------------------

int main() {
    benchmark();
    return 0;
}

