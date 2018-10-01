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
    #include "deoxysbc.h"
    #include "utils-opt.h"
}

// ---------------------------------------------------------------------

static const size_t NUM_ITERATIONS = 10000;
static const size_t NUM_BLOCKS_PER_CHUNK = 8;
static const size_t NUM_BYTES_PER_CHUNK = NUM_BLOCKS_PER_CHUNK
    * DEOXYS_BC_BLOCKLEN;
static const size_t NUM_MESSAGE_LENGTHS = 12;
static const size_t MESSAGE_LENGTHS[NUM_MESSAGE_LENGTHS] = {
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
};

// ---------------------------------------------------------------------

typedef struct {
    ALIGN(16)
    uint8_t key[DEOXYS_BC_128_KEYLEN];
    deoxys_bc_128_384_ctx_t ctx;
    ALIGN(16)
    uint8_t* plaintext;
    ALIGN(16)
    uint8_t* tweak;
    ALIGN(16)
    uint8_t* ciphertext;
    uint8_t tweak_domain;
    size_t tweak_counter;
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
    fill(context->key, DEOXYS_BC_128_KEYLEN);

    __m128i key = load(context->key);
    deoxys_bc_128_384_setup_key(&(context->ctx), key);
    context->plaintext = (uint8_t*)malloc(max_num_bytes);
    context->ciphertext = (uint8_t*)malloc(max_num_bytes);
    context->tweak = (uint8_t*)malloc(max_num_bytes);
    context->tweak_counter = 1;
    context->tweak_domain = 2;

    deoxys_bc_128_384_setup_base_counters(&(context->ctx),
                                          context->tweak_domain,
                                          context->tweak_counter);

    fill(context->plaintext, max_num_bytes);
    fill(context->tweak, max_num_bytes);
}

// ---------------------------------------------------------------------

static void finalize(benchmark_ctx_t* context) {
    free(context->plaintext);
    free(context->ciphertext);
    free(context->tweak);
}

// ---------------------------------------------------------------------

inline
static void run_operation(benchmark_ctx_t* context,
                          const size_t num_plaintext_bytes,
                          __m256i* tweaks,
                          __m128i* states) {
    size_t num_bytes = num_plaintext_bytes;
    uint8_t* plaintext_position = context->plaintext;
    uint8_t* ciphertext_position = context->ciphertext;
    uint8_t* tweak_position = context->tweak;

    while (num_bytes >= NUM_BYTES_PER_CHUNK) {
        load_eight(states, plaintext_position);
        avx_load_four(tweaks, tweak_position);

        deoxys_bc_128_384_encrypt_eight(&(context->ctx),
                                       context->tweak_counter,
                                       tweaks,
                                       states);
        store_eight(ciphertext_position, states);

        num_bytes -= NUM_BYTES_PER_CHUNK;
        ciphertext_position += NUM_BYTES_PER_CHUNK;
        plaintext_position += NUM_BYTES_PER_CHUNK;
        tweak_position += NUM_BYTES_PER_CHUNK;

        context->tweak_counter += NUM_BLOCKS_PER_CHUNK;
    }

    while (num_bytes >= DEOXYS_BC_BLOCKLEN) {
        __m128i plaintext = load(plaintext_position);
        __m128i tweak = load(tweak_position);

        deoxys_bc_128_384_encrypt(&(context->ctx),
                                  context->tweak_domain,
                                  context->tweak_counter,
                                  tweak,
                                  plaintext,
                                  states);

        store(ciphertext_position, states[0]);

        num_bytes -= DEOXYS_BC_BLOCKLEN;
        ciphertext_position += DEOXYS_BC_BLOCKLEN;
        plaintext_position += DEOXYS_BC_BLOCKLEN;
        tweak_position += DEOXYS_BC_BLOCKLEN;

        context->tweak_counter += 1;
    }
}

// ---------------------------------------------------------------------

static int benchmark() {
    // ---------------------------------------------------------------------
    // Initialization
    // ---------------------------------------------------------------------

    size_t num_plaintext_bytes;
    benchmark_ctx_t ctx;
    initialize(&ctx, MESSAGE_LENGTHS[NUM_MESSAGE_LENGTHS-1]);

    __m256i tweaks[4];
    __m128i states[NUM_BLOCKS_PER_CHUNK];

    // ---------------------------------------------------------------------
    // Warm up
    // ---------------------------------------------------------------------

    const uint64_t calibration = calibrate_timer();
    uint64_t t0;
    uint64_t t1;

    puts("#Bytes cpb");

    for (size_t i = 0; i < NUM_ITERATIONS / 4; ++i) {
        num_plaintext_bytes = 2048;
        run_operation(&ctx, num_plaintext_bytes, tweaks, states);
    }

    double timings[NUM_ITERATIONS];
    const uint32_t median = NUM_ITERATIONS / 2;

    // ---------------------------------------------------------------------
    // Benchmark
    // ---------------------------------------------------------------------

    for (size_t j = 0; j < NUM_MESSAGE_LENGTHS; ++j) {
        num_plaintext_bytes = MESSAGE_LENGTHS[j];

        t0 = get_time();
        t1 = get_time();

        for (size_t i = 0; i < NUM_ITERATIONS; ++i) {
            t0 = get_time();
            run_operation(&ctx, num_plaintext_bytes, tweaks, states);
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

