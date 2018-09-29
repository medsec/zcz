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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" {
    #include "deoxysbc.h"
    #include "foo.h"
    #include "utils.h"
}

#ifdef NI_ENABLED
    #include <emmintrin.h>
#endif

// ---------------------------------------------------------------------
// Static functions
// ---------------------------------------------------------------------

void assert_arrays_equal(const deoxys_bc_block_t expected,
                         const deoxys_bc_block_t actual) {
    const bool result = memcmp(expected, actual, DEOXYS_BC_BLOCKLEN); 
    EXPECT_TRUE(result == 0);

    if (result != 0) {
        print_hex("Expected", expected, DEOXYS_BC_BLOCKLEN);
        print_hex("But was ", actual, DEOXYS_BC_BLOCKLEN);
    }
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_128_encryption(
    const deoxys_bc_key_t key,
    const deoxys_bc_block_t plaintext,
    const deoxys_bc_block_t expected_ciphertext) {

    deoxys_bc_block_t ciphertext;
    uint32_t tweakey_size = 128;

    aesTweakEncrypt(tweakey_size, plaintext, key, ciphertext);
    assert_arrays_equal(expected_ciphertext, ciphertext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_256_encryption(
    const deoxys_bc_key_t key,
    const deoxys_bc_128_256_tweak_t tweak,
    const deoxys_bc_block_t plaintext,
    const deoxys_bc_block_t expected_ciphertext) {

    deoxys_bc_block_t ciphertext;
    uint32_t tweakey_size = 256;
    uint8_t tweakey[32];
    memcpy(tweakey, key, 16);
    memcpy(tweakey+16, tweak, 16);
    
    aesTweakEncrypt(tweakey_size, plaintext, tweakey, ciphertext);
    assert_arrays_equal(expected_ciphertext, ciphertext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_384_encryption(
    const deoxys_bc_key_t key,
    const deoxys_bc_128_384_tweak_t tweak,
    const deoxys_bc_block_t plaintext,
    const deoxys_bc_block_t expected_ciphertext) {

    deoxys_bc_block_t ciphertext;
    uint32_t tweakey_size = 384;
    uint8_t tweakey[48];
    memcpy(tweakey, key, 16);
    memcpy(tweakey+16, tweak, 32);

    aesTweakEncrypt(tweakey_size, plaintext, tweakey, ciphertext);
    assert_arrays_equal(expected_ciphertext, ciphertext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_128_decryption(
    const deoxys_bc_key_t key,
    const deoxys_bc_block_t ciphertext,
    const deoxys_bc_block_t expected_plaintext) {

    deoxys_bc_block_t plaintext;
    uint32_t tweakey_size = 128;

    aesTweakDecrypt(tweakey_size, ciphertext, key, plaintext);
    assert_arrays_equal(expected_plaintext, plaintext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_256_decryption(
    const deoxys_bc_key_t key,
    const deoxys_bc_128_256_tweak_t tweak,
    const deoxys_bc_block_t ciphertext,
    const deoxys_bc_block_t expected_plaintext) {

    deoxys_bc_block_t plaintext;
    uint32_t tweakey_size = 256;
    uint8_t tweakey[32];
    memcpy(tweakey, key, 16);
    memcpy(tweakey+16, tweak, 16);

    aesTweakDecrypt(tweakey_size, ciphertext, tweakey, plaintext);
    assert_arrays_equal(expected_plaintext, plaintext);
}

// ---------------------------------------------------------------------

static void test_deoxys_bc_128_384_decryption(
    const deoxys_bc_key_t key,
    const deoxys_bc_128_384_tweak_t tweak,
    const deoxys_bc_block_t ciphertext,
    const deoxys_bc_block_t expected_plaintext) {

    deoxys_bc_block_t plaintext;
    uint32_t tweakey_size = 384;
    uint8_t tweakey[48];
    memcpy(tweakey, key, 16);
    memcpy(tweakey+16, tweak, 32);

    aesTweakDecrypt(tweakey_size, ciphertext, tweakey, plaintext);
    assert_arrays_equal(expected_plaintext, plaintext);
}

// ---------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------

TEST(Orignal_DeoxysBC_128_128, encrypt) {
    const deoxys_bc_key_t key = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_block_t plaintext = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_block_t expected_ciphertext = { 
        0x98, 0x24, 0x07, 0x2a, 0xdb, 0x25, 0x39, 0x99, 
        0x12, 0x35, 0x3f, 0x57, 0x3a, 0x3a, 0x5f, 0xd7
    };
    test_deoxys_bc_128_128_encryption(key, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------------------

TEST(Orignal_DeoxysBC_128_256, encrypt) {
    const deoxys_bc_key_t key = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_128_256_tweak_t tweak = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_block_t plaintext = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_block_t expected_ciphertext = { 
        0x89, 0xcb, 0x26, 0x76, 0xbd, 0x73, 0x8e, 0xe4, 
        0x0c, 0x28, 0x6a, 0x7d, 0x29, 0x39, 0x73, 0x5b
    };
    test_deoxys_bc_128_256_encryption(key, tweak, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------------------

TEST(Orignal_DeoxysBC_128_384, encrypt) {
    const deoxys_bc_key_t key = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const deoxys_bc_128_384_tweak_t tweak = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const deoxys_bc_block_t plaintext = { 
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const deoxys_bc_block_t expected_ciphertext = { 
        0x0b, 0x72, 0x77, 0x0a, 0xd6, 0x2f, 0xf5, 0x4e,
        0x47, 0x57, 0x8c, 0x27, 0x37, 0xdb, 0x08, 0xf3
    };
    test_deoxys_bc_128_384_encryption(key, tweak, plaintext, expected_ciphertext);
}

// ---------------------------------------------------------------------

TEST(Orignal_DeoxysBC_128_128, decrypt) {
    const deoxys_bc_key_t key = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_block_t ciphertext = { 
        0x98, 0x24, 0x07, 0x2a, 0xdb, 0x25, 0x39, 0x99, 
        0x12, 0x35, 0x3f, 0x57, 0x3a, 0x3a, 0x5f, 0xd7
    };
    const deoxys_bc_block_t expected_plaintext = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    test_deoxys_bc_128_128_decryption(key, ciphertext, expected_plaintext);
}

// ---------------------------------------------------------------------

TEST(Orignal_DeoxysBC_128_256, decrypt) {
    const deoxys_bc_key_t key = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_128_256_tweak_t tweak = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_block_t ciphertext = { 
        0x89, 0xcb, 0x26, 0x76, 0xbd, 0x73, 0x8e, 0xe4, 
        0x0c, 0x28, 0x6a, 0x7d, 0x29, 0x39, 0x73, 0x5b
    };
    const deoxys_bc_block_t expected_plaintext = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    test_deoxys_bc_128_256_decryption(key, tweak, ciphertext, expected_plaintext);
}

// ---------------------------------------------------------------------

TEST(Orignal_DeoxysBC_128_384, decrypt) {
    const deoxys_bc_key_t key = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_128_384_tweak_t tweak = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    const deoxys_bc_block_t ciphertext = { 
        0x05, 0x9b, 0xcb, 0x43, 0x08, 0xaf, 0x07, 0xa5,
        0xaf, 0x48, 0x07, 0x81, 0x85, 0xa1, 0x0e, 0x26
    };
    const deoxys_bc_block_t expected_plaintext = { 
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    test_deoxys_bc_128_384_decryption(key, tweak, ciphertext, expected_plaintext);
}

// ---------------------------------------------------------------------

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
