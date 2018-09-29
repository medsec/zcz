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
#include <vector>

extern "C" {
    #include "deoxysbc.h"
    #include "utils.h"
    #include "zcz.h"
}

#include "zcz_test_case_context.h"
#include "json_parser.h"

#ifdef NI_ENABLED
    #include <emmintrin.h>
#endif

// ---------------------------------------------------------------------
// Static functions
// ---------------------------------------------------------------------

static void assert_arrays_equal(const uint8_t* expected,
                                const uint8_t* actual,
                                const size_t num_bytes) {
    bool result = 0;

    if (expected == nullptr) {
        result = (num_bytes == 0);
    } else {
        result = (memcmp(expected, actual, num_bytes) == 0);
    }

    EXPECT_TRUE(result);

    if (!result) {
        print_hex("Expected", expected, num_bytes);
        print_hex("But was ", actual, num_bytes);
    }
}

// ---------------------------------------------------------------------

static void run_zcz_encryption_test(const std::string& json_path,
                                    const bool use_basic = false) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    ZCZTestCaseContext context = json_parser.create_zcz_test_case(json_data);

    uint8_t* ciphertext = (uint8_t*)malloc(context.get_num_ciphertext_bytes());

    zcz_ctx_t ctx;
    zcz_keysetup(&ctx, context.key);

    if (use_basic) {
        zcz_basic_encrypt(&ctx,
                          context.plaintext,
                          context.get_num_plaintext_bytes(),
                          ciphertext);
    } else {
        zcz_encrypt(&ctx,
                    context.plaintext,
                    context.get_num_plaintext_bytes(),
                    ciphertext);
    }

    assert_arrays_equal(context.ciphertext,
                        ciphertext,
                        context.get_num_ciphertext_bytes());

    if (context.get_num_ciphertext_bytes() > 0) {
        free(ciphertext);
    }
}

// ---------------------------------------------------------

static void run_zcz_decryption_test(const std::string& json_path,
                                    const bool use_basic = false) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    ZCZTestCaseContext context = json_parser.create_zcz_test_case(json_data);

    uint8_t* plaintext = (uint8_t*)malloc(context.get_num_plaintext_bytes());

    zcz_ctx_t ctx;
    zcz_keysetup(&ctx, context.key);

    if (use_basic) {
        zcz_basic_decrypt(&ctx,
                          context.ciphertext,
                          context.get_num_ciphertext_bytes(),
                          plaintext);
    } else {
        zcz_decrypt(&ctx,
                    context.ciphertext,
                    context.get_num_ciphertext_bytes(),
                    plaintext);
    }

    assert_arrays_equal(context.plaintext,
                        plaintext,
                        context.get_num_plaintext_bytes());

    if (context.get_num_plaintext_bytes() > 0) {
        free(plaintext);
    }
}

// ---------------------------------------------------------------------
// Basic encryption test cases
// ---------------------------------------------------------------------

TEST(ZCZ_Basic, encrypt_empty_message) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_empty_message.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, encrypt_single_block) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_1_block.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, encrypt_two_blocks) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_2_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, encrypt_three_blocks) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_3_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, encrypt_four_blocks) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_4_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, encrypt_10_blocks) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_10_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, encrypt_256_blocks) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_256_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, encrypt_257_blocks) {
    run_zcz_encryption_test("testdata/zcz_basic_encrypt_257_blocks.json", true);
}

// ---------------------------------------------------------------------
// Basic decryption test cases
// ---------------------------------------------------------------------

TEST(ZCZ_Basic, decrypt_empty_message) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_empty_message.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, decrypt_single_block) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_1_block.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, decrypt_two_blocks) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_2_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, decrypt_three_blocks) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_3_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, decrypt_four_blocks) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_4_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, decrypt_10_blocks) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_10_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, decrypt_256_blocks) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_256_blocks.json", true);
}

// ---------------------------------------------------------

TEST(ZCZ_Basic, decrypt_257_blocks) {
    run_zcz_decryption_test("testdata/zcz_basic_decrypt_257_blocks.json", true);
}

// ---------------------------------------------------------------------
// Encryption test cases with the non-basic version
// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_empty_message) {
    run_zcz_encryption_test("testdata/zcz_encrypt_empty_message.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_single_block) {
    run_zcz_encryption_test("testdata/zcz_encrypt_1_block.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_two_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_2_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_three_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_3_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_four_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_4_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_256_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_256_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_257_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_257_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_510_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_510_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_511_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_511_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, encrypt_512_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_512_blocks.json");
}

// ---------------------------------------------------------------------

#ifndef NI_ENABLED  // Our optimized version works only for at most 512 blocks
TEST(ZCZ, encrypt_1024_blocks) {
    run_zcz_encryption_test("testdata/zcz_encrypt_1024_blocks.json");
}
#endif

// ---------------------------------------------------------------------
// Decryption test cases with the non-basic version
// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_empty_message) {
    run_zcz_decryption_test("testdata/zcz_decrypt_empty_message.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_single_block) {
    run_zcz_decryption_test("testdata/zcz_decrypt_1_block.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_two_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_2_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_three_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_3_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_four_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_4_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_256_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_256_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_257_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_257_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_510_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_510_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_511_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_511_blocks.json");
}

// ---------------------------------------------------------------------

TEST(ZCZ, decrypt_512_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_512_blocks.json");
}

// ---------------------------------------------------------------------

#ifndef NI_ENABLED  // Our optimized version works only for at most 512 blocks
TEST(ZCZ, decrypt_1024_blocks) {
    run_zcz_decryption_test("testdata/zcz_decrypt_1024_blocks.json");
}
#endif

// ---------------------------------------------------------------------

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
