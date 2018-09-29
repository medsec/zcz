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
#include <gtest/gtest.h>
#include <json/json.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "deoxysbc_opt_test_case_context.h"
#include "json_parser.h"
#include "memutils.h"

extern "C" {
    #include "deoxysbc.h"
    #include "utils-opt.h"
}

#ifdef NI_ENABLED
    #include <emmintrin.h>
#endif

enum DeoxysBCVariant {
    DEOXYS_BC_128_128,
    DEOXYS_BC_128_256,
    DEOXYS_BC_128_384
};

// ---------------------------------------------------------------------
// Static functions
// ---------------------------------------------------------------------

static void assert_arrays_equal(const uint8_t* expected,
                                const uint8_t* actual,
                                const size_t num_bytes) {
    const bool result = memcmp(expected, actual, num_bytes);
    EXPECT_TRUE(result == 0);

    if (result != 0) {
        print_hex("Expected", expected, num_bytes);
        print_hex("But was ", actual, num_bytes);
    }
}

// ---------------------------------------------------------------------

static void assert_equal(const __m128i expected, const __m128i actual) {
    const bool result = vcompare(expected, actual);
    EXPECT_TRUE(result == 0);

    if (result != 0) {
        print_hex_128("Expected", expected);
        print_hex_128("But was ", actual);
    }
}

// ---------------------------------------------------------------------

static void test_deoxysbc_128_384_encryption(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCOptTestCaseContext context = 
        json_parser.create_deoxys_bc_opt_test_case(json_data);

    __m128i key = load(context.key);
    __m128i plaintext = load(context.plaintext);
    __m128i tweak = load(context.tweak);
    __m128i expected_ciphertext = load(context.ciphertext);
    __m128i ciphertext = vzero;

    deoxys_bc_128_384_ctx_t ctx;
    deoxys_bc_128_384_setup_key(&ctx, key);

    deoxys_bc_128_384_encrypt(&ctx,
                              context.get_tweak_domain(),
                              context.get_tweak_counter(),
                              tweak,
                              plaintext,
                              &ciphertext);

    assert_equal(expected_ciphertext, ciphertext);
}

// ---------------------------------------------------------------------

static void test_deoxysbc_128_384_decryption(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCOptTestCaseContext context = 
        json_parser.create_deoxys_bc_opt_test_case(json_data);

    __m128i key = load(context.key);
    __m128i ciphertext = load(context.ciphertext);
    __m128i tweak = load(context.tweak);
    __m128i expected_plaintext = load(context.plaintext);
    __m128i plaintext = vzero;

    deoxys_bc_128_384_ctx_t ctx;
    deoxys_bc_128_384_setup_key(&ctx, key);
    deoxys_bc_128_384_setup_decryption_key(&ctx);

    deoxys_bc_128_384_decrypt(&ctx,
                              context.get_tweak_domain(),
                              context.get_tweak_counter(),
                              tweak,
                              ciphertext,
                              &plaintext);

    assert_equal(expected_plaintext, plaintext);
}

// ---------------------------------------------------------------------

static void test_deoxysbc_128_384_ecb_encryption(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCOptTestCaseContext context = 
        json_parser.create_deoxys_bc_opt_test_case(json_data);

    const size_t NUM_BLOCKS_PER_CHUNK = 8;
    const size_t NUM_BYTES_PER_CHUNK = NUM_BLOCKS_PER_CHUNK * DEOXYS_BC_BLOCKLEN;

    __m128i key = load(context.key);
    __m256i tweaks[4];
    __m128i states[NUM_BLOCKS_PER_CHUNK];

    uint8_t* ciphertext_array = (uint8_t*)malloc(context.get_num_ciphertext_bytes());
    uint8_t* plaintext_position = context.plaintext;
    uint8_t* ciphertext_position = ciphertext_array;
    uint8_t* tweak_position = context.tweak;
    size_t tweak_counter = context.get_tweak_counter();

    deoxys_bc_128_384_ctx_t ctx;
    deoxys_bc_128_384_setup_key(&ctx, key);

    size_t num_bytes = context.get_num_plaintext_bytes();
    deoxys_bc_128_384_setup_base_counters(&ctx,
                                          context.get_tweak_domain(),
                                          tweak_counter);

    while (num_bytes >= NUM_BYTES_PER_CHUNK) {
        load_eight(states, plaintext_position);
        avx_load_four(tweaks, tweak_position);

        deoxys_bc_128_384_encrypt_eight(&ctx,
                                       context.get_tweak_domain(),
                                       tweak_counter,
                                       tweaks,
                                       states);
        store_eight(ciphertext_position, states);

        num_bytes -= NUM_BYTES_PER_CHUNK;
        ciphertext_position += NUM_BYTES_PER_CHUNK;
        plaintext_position += NUM_BYTES_PER_CHUNK;
        tweak_position += NUM_BYTES_PER_CHUNK;
        tweak_counter += NUM_BLOCKS_PER_CHUNK;
    }

    while (num_bytes >= 4 * DEOXYS_BC_BLOCKLEN) {
        load_four(states, plaintext_position);
        avx_load_two(tweaks, tweak_position);

        deoxys_bc_128_384_encrypt_four(&ctx,
                                        context.get_tweak_domain(),
                                        tweak_counter,
                                        tweaks,
                                        states);
        store_four(ciphertext_position, states);

        num_bytes -= 4 * DEOXYS_BC_BLOCKLEN;
        ciphertext_position += 4 * DEOXYS_BC_BLOCKLEN;
        plaintext_position += 4 * DEOXYS_BC_BLOCKLEN;
        tweak_position += 4 * DEOXYS_BC_BLOCKLEN;
        tweak_counter += 4;
    }

    while (num_bytes >= DEOXYS_BC_BLOCKLEN) {
        __m128i plaintext = load(plaintext_position);
        __m128i tweak = load(tweak_position);

        deoxys_bc_128_384_encrypt(&ctx,
                                  context.get_tweak_domain(),
                                  tweak_counter,
                                  tweak,
                                  plaintext,
                                  states);

        store(ciphertext_position, states[0]);

        num_bytes -= DEOXYS_BC_BLOCKLEN;
        ciphertext_position += DEOXYS_BC_BLOCKLEN;
        plaintext_position += DEOXYS_BC_BLOCKLEN;
        tweak_position += DEOXYS_BC_BLOCKLEN;
        tweak_counter += 1;
    }

    assert_arrays_equal(context.ciphertext,
                        ciphertext_array,
                        context.get_num_ciphertext_bytes());

    free_if_used(ciphertext_array, context.get_num_ciphertext_bytes());
}

// ---------------------------------------------------------------------

static void test_deoxysbc_128_384_ecb_decryption(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCOptTestCaseContext context = 
        json_parser.create_deoxys_bc_opt_test_case(json_data);

    const size_t NUM_BLOCKS_PER_CHUNK = 8;
    const size_t NUM_BYTES_PER_CHUNK = NUM_BLOCKS_PER_CHUNK * DEOXYS_BC_BLOCKLEN;

    __m128i key = load(context.key);
    __m256i tweaks[4];
    __m128i states[NUM_BLOCKS_PER_CHUNK];

    uint8_t* plaintext_array = (uint8_t*)malloc(context.get_num_plaintext_bytes());
    uint8_t* ciphertext_position = context.ciphertext;
    uint8_t* plaintext_position = plaintext_array;
    uint8_t* tweak_position = context.tweak;
    size_t tweak_counter = context.get_tweak_counter();

    deoxys_bc_128_384_ctx_t ctx;
    deoxys_bc_128_384_setup_key(&ctx, key);
    deoxys_bc_128_384_setup_decryption_key(&ctx);
    deoxys_bc_128_384_setup_base_counters(&ctx,
                                          context.get_tweak_domain(),
                                          tweak_counter);

    size_t num_bytes = context.get_num_plaintext_bytes();

    while (num_bytes >= NUM_BYTES_PER_CHUNK) {
        load_eight(states, ciphertext_position);
        avx_load_four(tweaks, tweak_position);

        deoxys_bc_128_384_decrypt_eight(&ctx,
                                       context.get_tweak_domain(),
                                       tweak_counter,
                                       tweaks,
                                       states);
        store_eight(plaintext_position, states);

        num_bytes -= NUM_BYTES_PER_CHUNK;
        ciphertext_position += NUM_BYTES_PER_CHUNK;
        plaintext_position += NUM_BYTES_PER_CHUNK;
        tweak_position += NUM_BYTES_PER_CHUNK;
        tweak_counter += NUM_BLOCKS_PER_CHUNK;
    }

    while (num_bytes >= 4 * DEOXYS_BC_BLOCKLEN) {
        load_four(states, ciphertext_position);
        avx_load_two(tweaks, tweak_position);

        deoxys_bc_128_384_decrypt_four(&ctx,
                                        context.get_tweak_domain(),
                                        tweak_counter,
                                        tweaks,
                                        states);
        store_four(plaintext_position, states);

        num_bytes -= 4 * DEOXYS_BC_BLOCKLEN;
        ciphertext_position += 4 * DEOXYS_BC_BLOCKLEN;
        plaintext_position += 4 * DEOXYS_BC_BLOCKLEN;
        tweak_position += 4 * DEOXYS_BC_BLOCKLEN;
        tweak_counter += 4;
    }

    while (num_bytes >= DEOXYS_BC_BLOCKLEN) {
        __m128i ciphertext = load(ciphertext_position);
        __m128i tweak = load(tweak_position);

        deoxys_bc_128_384_decrypt(&ctx,
                                  context.get_tweak_domain(),
                                  tweak_counter,
                                  tweak,
                                  ciphertext,
                                  states);

        store(plaintext_position, states[0]);

        num_bytes -= DEOXYS_BC_BLOCKLEN;
        ciphertext_position += DEOXYS_BC_BLOCKLEN;
        plaintext_position += DEOXYS_BC_BLOCKLEN;
        tweak_position += DEOXYS_BC_BLOCKLEN;
        tweak_counter += 1;
    }

    assert_arrays_equal(context.plaintext,
                        plaintext_array,
                        context.get_num_plaintext_bytes());

    free_if_used(plaintext_array, context.get_num_plaintext_bytes());
}

// ---------------------------------------------------------------------
// Single-block test cases
// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt) {
    test_deoxysbc_128_384_encryption("testdata/deoxysbc_128_384_encrypt_opt.json");
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt) {
    test_deoxysbc_128_384_decryption("testdata/deoxysbc_128_384_encrypt_opt.json");
}

// ---------------------------------------------------------------------
// Multi-block encryption test cases
// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt_four_blocks) {
    test_deoxysbc_128_384_ecb_encryption(
        "testdata/deoxysbc_128_384_encrypt_4_blocks_opt.json"
    );
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt_256_blocks_zero_ctr) {
    test_deoxysbc_128_384_ecb_encryption(
        "testdata/deoxysbc_128_384_encrypt_256_blocks_zero_ctr_opt.json"
    );
}

// ---------------------------------------------------------------------
// Multi-block decryption test cases
// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt_four_blocks) {
    test_deoxysbc_128_384_ecb_decryption(
        "testdata/deoxysbc_128_384_encrypt_4_blocks_opt.json"
    );
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt_256_blocks_zero_ctr) {
    test_deoxysbc_128_384_ecb_decryption(
        "testdata/deoxysbc_128_384_encrypt_256_blocks_zero_ctr_opt.json"
    );
}

// ---------------------------------------------------------------------

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
