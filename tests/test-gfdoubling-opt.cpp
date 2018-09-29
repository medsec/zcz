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

extern "C" {
    #include "gfmul.h"
    #include "utils-opt.h"
}

#include "memutils.h"
#include "gf_doubling_test_case_context.h"
#include "json_parser.h"

#ifdef NI_ENABLED
    #include <emmintrin.h>
#endif

// ---------------------------------------------------------------------

static const size_t BLOCKLEN = 16;


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

static void gf_double_opt(uint8_t* output, 
                          const uint8_t* input, 
                          const size_t num_input_bytes) {
    __m128i input_block;
    __m128i output_block;
    __m128i hash;
    __m128i tmp;
    hash = vzero;

    EXPECT_TRUE(num_input_bytes >= BLOCKLEN);
    EXPECT_TRUE((num_input_bytes & 0x0F) == 0);

    size_t num_remaining_bytes = num_input_bytes;
    const uint8_t* input_position = input;

    while (num_remaining_bytes >= BLOCKLEN) {
        input_block = loadu(input_position);
        gf_2_128_double(hash, output_block, tmp);
        hash = vxor(output_block, input_block);

        // print_hex_128("input ", input_block);
        // print_hex_128("output", output_block);
        // print_hex_128("hash  ", hash);

        input_position += BLOCKLEN;
        num_remaining_bytes -= BLOCKLEN;
    }

    storeu(output, hash);
}

// ---------------------------------------------------------------------

static void test_gf_double_opt(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    
    GFDoublingTestCaseContext context = 
        json_parser.create_gf_doubling_test_case(json_data);

    EXPECT_EQ(BLOCKLEN, context.get_num_output_bytes());
    
    uint8_t actual_hash[BLOCKLEN];

    gf_double_opt(actual_hash, context.input, context.get_num_input_bytes());
    assert_arrays_equal(context.output, actual_hash, BLOCKLEN);
}

// ---------------------------------------------------------------------

static void gf_double_opt_multi(uint8_t* output, 
                                const uint8_t* input, 
                                const size_t num_input_bytes) {
    __m128i input_blocks[8];
    __m128i output_block;
    __m128i hash = vzero;
    __m128i tmp;

    EXPECT_TRUE(num_input_bytes >= BLOCKLEN);
    EXPECT_TRUE((num_input_bytes & 0x0F) == 0);

    size_t num_remaining_bytes = num_input_bytes;
    const uint8_t* input_position = input;

    while (num_remaining_bytes >= 8 * BLOCKLEN) {
        load_eight(input_blocks, input_position);
        
        // for (size_t i = 0; i < 8; ++i) {
        //     printf("%2zu ", i);
        //     print_hex_128("input ", input_blocks[i]);
        // }

        hash = gf_2_128_double_eight(hash, input_blocks);

        // print_hex_128("hash  ", hash);

        input_position += 8 * BLOCKLEN;
        num_remaining_bytes -= 8 * BLOCKLEN;
    }

    while (num_remaining_bytes >= BLOCKLEN) {
        input_blocks[0] = loadu(input_position);
        gf_2_128_double(hash, output_block, tmp);
        hash = vxor(output_block, input_blocks[0]);

        // print_hex_128("input ", input_blocks[0]);
        // print_hex_128("output", output_block);
        // print_hex_128("hash  ", hash);

        input_position += BLOCKLEN;
        num_remaining_bytes -= BLOCKLEN;
    }

    storeu(output, hash);
}

// ---------------------------------------------------------------------

static void test_gf_double_opt_multi(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    
    GFDoublingTestCaseContext context = 
        json_parser.create_gf_doubling_test_case(json_data);

    EXPECT_EQ(BLOCKLEN, context.get_num_output_bytes());
    
    uint8_t actual_hash[BLOCKLEN];

    gf_double_opt_multi(actual_hash,
                        context.input,
                        context.get_num_input_bytes());
    assert_arrays_equal(context.output, actual_hash, BLOCKLEN);
}

// ---------------------------------------------------------------------

static void gf_times_four_opt(uint8_t* output, 
                          const uint8_t* input, 
                          const size_t num_input_bytes) {
    __m128i input_block;
    __m128i output_block;
    __m128i hash;
    __m128i tmp;
    hash = vzero;

    EXPECT_TRUE(num_input_bytes >= BLOCKLEN);
    EXPECT_TRUE((num_input_bytes & 0x0F) == 0);

    size_t num_remaining_bytes = num_input_bytes;
    const uint8_t* input_position = input;

    while (num_remaining_bytes >= BLOCKLEN) {
        input_block = loadu(input_position);
        gf_2_128_times_four(hash, output_block, tmp);
        hash = vxor(output_block, input_block);

        // print_hex_128("input ", input_block);
        // print_hex_128("output", output_block);
        // print_hex_128("hash  ", hash);

        input_position += BLOCKLEN;
        num_remaining_bytes -= BLOCKLEN;
    }

    storeu(output, hash);
}

// ---------------------------------------------------------------------

static void test_gf_times_four_opt(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    
    GFDoublingTestCaseContext context = 
        json_parser.create_gf_doubling_test_case(json_data);

    EXPECT_EQ(BLOCKLEN, context.get_num_output_bytes());
    
    uint8_t actual_hash[BLOCKLEN];

    gf_times_four_opt(actual_hash, context.input, context.get_num_input_bytes());
    assert_arrays_equal(context.output, actual_hash, BLOCKLEN);
}

// ---------------------------------------------------------------------

static void gf_times_four_opt_multi(uint8_t* output, 
                                const uint8_t* input, 
                                const size_t num_input_bytes) {
    __m128i input_blocks[8];
    __m128i output_block;
    __m128i hash = vzero;
    __m128i tmp;

    EXPECT_TRUE(num_input_bytes >= BLOCKLEN);
    EXPECT_TRUE((num_input_bytes & 0x0F) == 0);

    size_t num_remaining_bytes = num_input_bytes;
    const uint8_t* input_position = input;

    while (num_remaining_bytes >= 8 * BLOCKLEN) {
        load_eight(input_blocks, input_position);
        
        // for (size_t i = 0; i < 9; ++i) {
        //     printf("%2zu ", i);
        //     print_hex_128("input ", input_blocks[i]);
        // }

        hash = gf_2_128_times_four_eight(hash, input_blocks);

        // print_hex_128("hash  ", hash);

        input_position += 8 * BLOCKLEN;
        num_remaining_bytes -= 8 * BLOCKLEN;
    }

    while (num_remaining_bytes >= BLOCKLEN) {
        input_blocks[0] = loadu(input_position);
        gf_2_128_times_four(hash, output_block, tmp);
        hash = vxor(output_block, input_blocks[0]);

        // print_hex_128("input ", input_blocks[0]);
        // print_hex_128("output", output_block);
        // print_hex_128("hash  ", *hash);

        input_position += BLOCKLEN;
        num_remaining_bytes -= BLOCKLEN;
    }

    storeu(output, hash);
}

// ---------------------------------------------------------------------

static void test_gf_times_four_opt_multi(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    
    GFDoublingTestCaseContext context = 
        json_parser.create_gf_doubling_test_case(json_data);

    EXPECT_EQ(BLOCKLEN, context.get_num_output_bytes());
    
    uint8_t actual_hash[BLOCKLEN];

    gf_times_four_opt_multi(actual_hash,
                        context.input,
                        context.get_num_input_bytes());
    assert_arrays_equal(context.output, actual_hash, BLOCKLEN);
}

// ---------------------------------------------------------------------

// ---------------------------------------------------------------------
// GF Doubling test cases
// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_1_block) {
    test_gf_double_opt("testdata/gf_doubling_1_block.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_2_blocks) {
    test_gf_double_opt("testdata/gf_doubling_2_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_2_blocks_no_mask) {
    test_gf_double_opt("testdata/gf_doubling_2_blocks_no_mask.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_8_blocks) {
    test_gf_double_opt("testdata/gf_doubling_8_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_9_blocks) {
    test_gf_double_opt("testdata/gf_doubling_9_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_16_blocks) {
    test_gf_double_opt("testdata/gf_doubling_16_blocks.json");
}

// ---------------------------------------------------------------------
// Test doubling on multiple blocks in parallel
// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_8_blocks_multi) {
    test_gf_double_opt_multi("testdata/gf_doubling_8_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_9_blocks_multi) {
    test_gf_double_opt_multi("testdata/gf_doubling_9_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, opt_16_blocks_multi) {
    test_gf_double_opt_multi("testdata/gf_doubling_16_blocks.json");
}

// ---------------------------------------------------------------------
// GF x4 Multiplication test cases
// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_1_block) {
    test_gf_times_four_opt("testdata/gf_times_four_1_block.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_2_blocks) {
    test_gf_times_four_opt("testdata/gf_times_four_2_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_2_blocks_no_mask) {
    test_gf_times_four_opt("testdata/gf_times_four_2_blocks_no_mask.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_8_blocks) {
    test_gf_times_four_opt("testdata/gf_times_four_8_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_9_blocks) {
    test_gf_times_four_opt("testdata/gf_times_four_9_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_16_blocks) {
    test_gf_times_four_opt("testdata/gf_times_four_16_blocks.json");
}

// ---------------------------------------------------------------------
// Test doubling on multiple blocks in parallel
// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_8_blocks_multi) {
    test_gf_times_four_opt_multi("testdata/gf_times_four_8_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_9_blocks_multi) {
    test_gf_times_four_opt_multi("testdata/gf_times_four_9_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, opt_16_blocks_multi) {
    test_gf_times_four_opt_multi("testdata/gf_times_four_16_blocks.json");
}

// ---------------------------------------------------------------------

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
