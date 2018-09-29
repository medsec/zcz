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
    #include "utils.h"
}

#include "memutils.h"
#include "gf_doubling_test_case_context.h"
#include "json_parser.h"

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

static void gf_double_ref(uint8_t hash[BLOCKLEN],
                          const uint8_t* input, 
                          const size_t num_input_bytes) {
    uint8_t output_block[BLOCKLEN];
    memset(hash, 0x00, BLOCKLEN);

    EXPECT_TRUE(num_input_bytes >= BLOCKLEN);
    EXPECT_TRUE((num_input_bytes & 0x0F) == 0);

    size_t num_remaining_bytes = num_input_bytes;
    const uint8_t* input_position = input;

    while (num_remaining_bytes >= BLOCKLEN) {
        gf_double(output_block, hash, BLOCKLEN);
        vxor(hash, output_block, input_position, BLOCKLEN);

        // print_hex("input ", input_position, BLOCKLEN);
        // print_hex("output", output_block, BLOCKLEN);
        // print_hex("hash  ", hash, BLOCKLEN);

        input_position += BLOCKLEN;
        num_remaining_bytes -= BLOCKLEN;
    }
}

// ---------------------------------------------------------------------

static void test_gf_double_ref(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);

    GFDoublingTestCaseContext context = 
        json_parser.create_gf_doubling_test_case(json_data);

    EXPECT_EQ(BLOCKLEN, context.get_num_output_bytes());
    
    uint8_t actual_hash[BLOCKLEN];

    gf_double_ref(actual_hash, context.input, context.get_num_input_bytes());
    assert_arrays_equal(context.output, actual_hash, BLOCKLEN);
}

// ---------------------------------------------------------------------

static void gf_times_four_ref(uint8_t hash[BLOCKLEN],
                          const uint8_t* input, 
                          const size_t num_input_bytes) {
    uint8_t output_block[BLOCKLEN];
    memset(hash, 0x00, BLOCKLEN);

    EXPECT_TRUE(num_input_bytes >= BLOCKLEN);
    EXPECT_TRUE((num_input_bytes & 0x0F) == 0);

    size_t num_remaining_bytes = num_input_bytes;
    const uint8_t* input_position = input;

    while (num_remaining_bytes >= BLOCKLEN) {
        gf_times_four(output_block, hash, BLOCKLEN);
        vxor(hash, output_block, input_position, BLOCKLEN);

        // print_hex("input ", input_position, BLOCKLEN);
        // print_hex("output", output_block, BLOCKLEN);
        // print_hex("hash  ", hash, BLOCKLEN);

        input_position += BLOCKLEN;
        num_remaining_bytes -= BLOCKLEN;
    }
}

// ---------------------------------------------------------------------

static void test_gf_times_four_ref(const std::string& json_path) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);

    GFDoublingTestCaseContext context = 
        json_parser.create_gf_doubling_test_case(json_data);

    EXPECT_EQ(BLOCKLEN, context.get_num_output_bytes());
    
    uint8_t actual_hash[BLOCKLEN];

    gf_times_four_ref(actual_hash, context.input, context.get_num_input_bytes());
    assert_arrays_equal(context.output, actual_hash, BLOCKLEN);
}

// ---------------------------------------------------------------------
// Doubling test cases
// ---------------------------------------------------------------------

TEST(GF_DOUBLING, ref_1_block) {
    test_gf_double_ref("testdata/gf_doubling_1_block.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, ref_2_blocks) {
    test_gf_double_ref("testdata/gf_doubling_2_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, ref_2_blocks_no_mask) {
    test_gf_double_ref("testdata/gf_doubling_2_blocks_no_mask.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, ref_8_blocks) {
    test_gf_double_ref("testdata/gf_doubling_8_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, ref_9_blocks) {
    test_gf_double_ref("testdata/gf_doubling_9_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_DOUBLING, ref_16_blocks) {
    test_gf_double_ref("testdata/gf_doubling_16_blocks.json");
}

// ---------------------------------------------------------------------
// Doubling test cases
// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, ref_1_block) {
    test_gf_times_four_ref("testdata/gf_times_four_1_block.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, ref_2_blocks) {
    test_gf_times_four_ref("testdata/gf_times_four_2_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, ref_2_blocks_no_mask) {
    test_gf_times_four_ref("testdata/gf_times_four_2_blocks_no_mask.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, ref_8_blocks) {
    test_gf_times_four_ref("testdata/gf_times_four_8_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, ref_9_blocks) {
    test_gf_times_four_ref("testdata/gf_times_four_9_blocks.json");
}

// ---------------------------------------------------------------------

TEST(GF_TIMES_FOUR, ref_16_blocks) {
    test_gf_times_four_ref("testdata/gf_times_four_16_blocks.json");
}

// ---------------------------------------------------------------------

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
