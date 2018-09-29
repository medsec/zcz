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
    #include "deoxysbc.h"
    #include "utils.h"
}

#include "deoxysbc_test_case_context.h"
#include "json_parser.h"

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
    const int result = memcmp(expected, actual, num_bytes);
    EXPECT_TRUE(result == 0);

    if (result != 0) {
        print_hex("Expected", expected, num_bytes);
        print_hex("But was ", actual, num_bytes);
    }
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_128_encryption(
        const deoxys_bc_key_t key,
        const deoxys_bc_block_t plaintext,
        deoxys_bc_block_t ciphertext) {
    deoxys_bc_128_128_ctx_t ctx;
    deoxys_bc_128_128_encrypt(&ctx, key, plaintext, ciphertext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_256_encryption(
        const deoxys_bc_key_t key,
        const deoxys_bc_128_256_tweak_t tweak,
        const deoxys_bc_block_t plaintext,
        deoxys_bc_block_t ciphertext) {
    deoxys_bc_128_256_ctx_t ctx;
    deoxys_bc_128_256_encrypt(&ctx, key, tweak, plaintext, ciphertext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_384_encryption(
        const deoxys_bc_key_t key,
        const deoxys_bc_128_384_tweak_t tweak,
        const deoxys_bc_block_t plaintext,
        deoxys_bc_block_t ciphertext) {
    deoxys_bc_128_384_ctx_t ctx;
    deoxys_bc_128_384_encrypt(&ctx, key, tweak, plaintext, ciphertext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_128_decryption(
        const deoxys_bc_key_t key,
        const deoxys_bc_block_t ciphertext,
        deoxys_bc_block_t plaintext) {
    deoxys_bc_128_128_ctx_t ctx;
    deoxys_bc_128_128_decrypt(&ctx, key, ciphertext, plaintext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_256_decryption(
        const deoxys_bc_key_t key,
        const deoxys_bc_128_256_tweak_t tweak,
        const deoxys_bc_block_t ciphertext,
        deoxys_bc_block_t plaintext) {
    deoxys_bc_128_256_ctx_t ctx;
    deoxys_bc_128_256_decrypt(&ctx, key, tweak, ciphertext, plaintext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_384_decryption(
        const deoxys_bc_key_t key,
        const deoxys_bc_128_384_tweak_t tweak,
        const deoxys_bc_block_t ciphertext,
        deoxys_bc_block_t plaintext) {
    deoxys_bc_128_384_ctx_t ctx;
    deoxys_bc_128_384_decrypt(&ctx, key, tweak, ciphertext, plaintext);
}

// ---------------------------------------------------------------------

static void test_encryption(const std::string& json_path,
                            const DeoxysBCVariant& variant) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCTestCaseContext context = json_parser.create_deoxys_bc_test_case(
        json_data
    );

    uint8_t* ciphertext = (uint8_t*)malloc(context.get_num_ciphertext_bytes());

    switch (variant) {
        case DeoxysBCVariant::DEOXYS_BC_128_128:
            test_deoxys_bc_128_128_encryption(context.key,
                                              context.plaintext,
                                              ciphertext);
            break;
        case DeoxysBCVariant::DEOXYS_BC_128_256:
            test_deoxys_bc_128_256_encryption(context.key,
                                              context.tweak,
                                              context.plaintext,
                                              ciphertext);
            break;
        case DeoxysBCVariant::DEOXYS_BC_128_384:
            test_deoxys_bc_128_384_encryption(context.key,
                                              context.tweak,
                                              context.plaintext,
                                              ciphertext);
            break;
        default:
            return;
    }

    assert_arrays_equal(context.ciphertext,
                        ciphertext,
                        context.get_num_ciphertext_bytes());

    if (context.get_num_ciphertext_bytes() > 0) {
        free(ciphertext);
    }
}

// ---------------------------------------------------------------------

static void test_decryption(const std::string& json_path,
                            const DeoxysBCVariant& variant) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCTestCaseContext context = json_parser.create_deoxys_bc_test_case(
        json_data
    );

    uint8_t* plaintext = (uint8_t*)malloc(context.get_num_plaintext_bytes());

    switch (variant) {
        case DeoxysBCVariant::DEOXYS_BC_128_128:
            test_deoxys_bc_128_128_decryption(context.key,
                                              context.ciphertext,
                                              plaintext);
            break;
        case DeoxysBCVariant::DEOXYS_BC_128_256:
            test_deoxys_bc_128_256_decryption(context.key,
                                              context.tweak,
                                              context.ciphertext,
                                              plaintext);
            break;
        case DeoxysBCVariant::DEOXYS_BC_128_384:
            test_deoxys_bc_128_384_decryption(context.key,
                                              context.tweak,
                                              context.ciphertext,
                                              plaintext);
            break;
        default:
            return;
    }

    assert_arrays_equal(context.plaintext,
                        plaintext,
                        context.get_num_plaintext_bytes());

    if (context.get_num_plaintext_bytes() > 0) {
        free(plaintext);
    }
}

// ---------------------------------------------------------------------

static void test_ecb_encryption(const std::string& json_path,
                                const DeoxysBCVariant& variant) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCTestCaseContext context = json_parser.create_deoxys_bc_test_case(
        json_data
    );

    uint8_t* ciphertext = (uint8_t*)malloc(context.get_num_ciphertext_bytes());

    const size_t num_blocks = context.get_num_plaintext_bytes() / DEOXYS_BC_BLOCKLEN;
    size_t tweak_position = 0;
    size_t plaintext_position = 0;
    size_t ciphertext_position = 0;

    for (size_t i = 0; i < num_blocks; ++i) {
        switch (variant) {
            case DeoxysBCVariant::DEOXYS_BC_128_128:
                test_deoxys_bc_128_128_encryption(context.key,
                                                  context.plaintext + plaintext_position,
                                                  ciphertext + ciphertext_position);
                break;
            case DeoxysBCVariant::DEOXYS_BC_128_256:
                test_deoxys_bc_128_256_encryption(context.key,
                                                  context.tweak + tweak_position,
                                                  context.plaintext + plaintext_position,
                                                  ciphertext + ciphertext_position);
                tweak_position += DEOXYS_BC_128_256_TWEAK_LEN;
                break;
            case DeoxysBCVariant::DEOXYS_BC_128_384:
                test_deoxys_bc_128_384_encryption(context.key,
                                                  context.tweak + tweak_position,
                                                  context.plaintext + plaintext_position,
                                                  ciphertext + ciphertext_position);
                tweak_position += DEOXYS_BC_128_384_TWEAK_LEN;
                break;
            default:
                return;
        }

        plaintext_position += DEOXYS_BC_BLOCKLEN;
        ciphertext_position += DEOXYS_BC_BLOCKLEN;
    }

    assert_arrays_equal(context.ciphertext,
                        ciphertext,
                        context.get_num_ciphertext_bytes());

    if (context.get_num_ciphertext_bytes() > 0) {
        free(ciphertext);
    }
}

// ---------------------------------------------------------------------

static void test_ecb_decryption(const std::string& json_path,
                                const DeoxysBCVariant& variant) {
    JSONParser json_parser;
    const Json::Value json_data = json_parser.parse(json_path);
    DeoxysBCTestCaseContext context = json_parser.create_deoxys_bc_test_case(
        json_data
    );

    uint8_t* plaintext = (uint8_t*)malloc(context.get_num_plaintext_bytes());

    const size_t num_blocks = context.get_num_ciphertext_bytes() / DEOXYS_BC_BLOCKLEN;
    size_t tweak_position = 0;
    size_t plaintext_position = 0;
    size_t ciphertext_position = 0;

    for (size_t i = 0; i < num_blocks; ++i) {
        switch (variant) {
            case DeoxysBCVariant::DEOXYS_BC_128_128:
                test_deoxys_bc_128_128_decryption(context.key,
                                                  context.ciphertext + ciphertext_position,
                                                  plaintext + plaintext_position);
                break;
            case DeoxysBCVariant::DEOXYS_BC_128_256:
                test_deoxys_bc_128_256_decryption(context.key,
                                                  context.tweak + tweak_position,
                                                  context.ciphertext + ciphertext_position,
                                                  plaintext + plaintext_position);
                tweak_position += DEOXYS_BC_128_256_TWEAK_LEN;
                break;
            case DeoxysBCVariant::DEOXYS_BC_128_384:
                test_deoxys_bc_128_384_decryption(context.key,
                                                  context.tweak + tweak_position,
                                                  context.ciphertext + ciphertext_position,
                                                  plaintext + plaintext_position);
                tweak_position += DEOXYS_BC_128_384_TWEAK_LEN;
                break;
            default:
                return;
        }

        plaintext_position += DEOXYS_BC_BLOCKLEN;
        ciphertext_position += DEOXYS_BC_BLOCKLEN;
    }

    assert_arrays_equal(context.plaintext,
                        plaintext,
                        context.get_num_plaintext_bytes());

    if (context.get_num_plaintext_bytes() > 0) {
        free(plaintext);
    }
}

// ---------------------------------------------------------------------
// Single-block test cases
// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, encrypt) {
    test_encryption("testdata/deoxysbc_128_128_encrypt.json",
                    DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, encrypt) {
    test_encryption("testdata/deoxysbc_128_256_encrypt.json",
                    DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt) {
    test_encryption("testdata/deoxysbc_128_384_encrypt.json",
                    DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, decrypt) {
    test_decryption("testdata/deoxysbc_128_128_encrypt.json",
                    DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, decrypt) {
    test_decryption("testdata/deoxysbc_128_256_encrypt.json",
                    DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt) {
    test_decryption("testdata/deoxysbc_128_384_encrypt.json",
                    DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------
// Multi-block encryption test cases
// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, encrypt_four_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_128_encrypt_4_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, encrypt_256_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_128_encrypt_256_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, encrypt_257_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_128_encrypt_257_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, encrypt_four_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_256_encrypt_4_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, encrypt_256_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_256_encrypt_256_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, encrypt_257_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_256_encrypt_257_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt_four_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_384_encrypt_4_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt_256_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_384_encrypt_256_blocks.json",
                    DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt_256_blocks_zero_ctr) {
    test_ecb_encryption("testdata/deoxysbc_128_384_encrypt_256_blocks_zero_ctr.json",
                        DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, encrypt_257_blocks) {
    test_ecb_encryption("testdata/deoxysbc_128_384_encrypt_257_blocks.json",
                    DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------
// Multi-block decryption test cases
// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, decrypt_four_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_128_encrypt_4_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, decrypt_256_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_128_encrypt_256_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_128, decrypt_257_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_128_encrypt_257_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_128);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, decrypt_four_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_256_encrypt_4_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, decrypt_256_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_256_encrypt_256_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_256, decrypt_257_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_256_encrypt_257_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_256);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt_four_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_384_encrypt_4_blocks.json",
                        DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt_256_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_384_encrypt_256_blocks.json",
                    DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt_256_blocks_zero_ctr) {
    test_ecb_decryption("testdata/deoxysbc_128_384_encrypt_256_blocks_zero_ctr.json",
                        DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

TEST(DeoxysBC_128_384, decrypt_257_blocks) {
    test_ecb_decryption("testdata/deoxysbc_128_384_encrypt_257_blocks.json",
                    DeoxysBCVariant::DEOXYS_BC_128_384);
}

// ---------------------------------------------------------------------

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
