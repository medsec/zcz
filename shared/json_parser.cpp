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
#include "json_parser.h"

#include <cassert>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <vector>

#include "deoxysbc_test_case_context.h"
#include "deoxysbc_opt_test_case_context.h"
#include "gf_doubling_test_case_context.h"
#include "zcz_test_case_context.h"
#include "memutils.h"

// ---------------------------------------------------------
// Constants
// ---------------------------------------------------------

const char JSONParser::KEY[] = "key";
const char JSONParser::TWEAK[] = "tweak";
const char JSONParser::PLAINTEXT[] = "plaintext";
const char JSONParser::CIPHERTEXT[] = "ciphertext";
const char JSONParser::NUM_PLAINTEXT_BYTES[] = "num_plaintext_bytes";
const char JSONParser::NUM_CIPHERTEXT_BYTES[] = "num_ciphertext_bytes";
const char JSONParser::NUM_TWEAK_BYTES[] = "num_tweak_bytes";
const char JSONParser::TWEAK_DOMAIN[] = "tweak_domain";
const char JSONParser::TWEAK_COUNTER[] = "tweak_counter";
const char JSONParser::NUM_INPUT_BYTES[] = "num_input_bytes";
const char JSONParser::NUM_OUTPUT_BYTES[] = "num_output_bytes";
const char JSONParser::INPUT[] = "input";
const char JSONParser::OUTPUT[] = "output";


// ---------------------------------------------------------

static uint64_t to_uint64_t(const std::vector<uint8_t>& bytes) {
    assert(bytes.size() == 8);
    return ((uint64_t)(bytes[0]) << 56)
        | ((uint64_t)(bytes[1]) << 48)
        | ((uint64_t)(bytes[2]) << 40)
        | ((uint64_t)(bytes[3]) << 32)
        | ((uint64_t)(bytes[4]) << 24)
        | ((uint64_t)(bytes[5]) << 16)
        | ((uint64_t)(bytes[6]) <<  8)
        | ((uint64_t)(bytes[7]));
}

// ---------------------------------------------------------

static uint8_t to_uint8_t(const std::vector<uint8_t>& bytes) {
    return bytes[0];
}

// ----------------------------------------------------------

static std::vector<uint8_t> to_byte_array(const std::string& hex_string) {
    std::vector<uint8_t> bytes;

    for (unsigned int i = 0; i < hex_string.length(); i += 2) {
        std::string byteString = hex_string.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

// ---------------------------------------------------------

static std::vector<uint8_t> to_vector(const Json::Value& json_string) {
    std::string hex_string;

    if (json_string.isString()) {
        hex_string = json_string.asString();
    } else if (json_string.isArray()) {
        std::stringstream stream;

        for (auto& letter : json_string) {
            stream << letter;
        }

        hex_string = stream.str();
    }

    return to_byte_array(hex_string);
}

// ---------------------------------------------------------
// Public API
// ---------------------------------------------------------

Json::Value JSONParser::parse(const std::string& path) {
    Json::Value result;
    std::ifstream in_file_stream(path);

    if (!in_file_stream.good()) {
        std::cerr << path << " yielded a bad file stream" << std::endl;
        return result;
    }

    in_file_stream >> result;
    return result;
}

// ---------------------------------------------------------

ZCZTestCaseContext JSONParser::create_zcz_test_case(
    const Json::Value &json_data) {
    const size_t num_plaintext_bytes =
        json_data[JSONParser::NUM_PLAINTEXT_BYTES].asUInt64();
    const size_t num_ciphertext_bytes =
        json_data[JSONParser::NUM_CIPHERTEXT_BYTES].asUInt64();
    const std::vector<uint8_t> key =
        to_vector(json_data[JSONParser::KEY]);
    const std::vector<uint8_t> plaintext =
        to_vector(json_data[JSONParser::PLAINTEXT]);
    const std::vector<uint8_t> ciphertext =
        to_vector(json_data[JSONParser::CIPHERTEXT]);

    ZCZTestCaseContext context(num_plaintext_bytes,
                            num_ciphertext_bytes,
                            key,
                            plaintext,
                            ciphertext);

    return context;
}

// ---------------------------------------------------------

DeoxysBCTestCaseContext JSONParser::create_deoxys_bc_test_case(
        const Json::Value& json_data) {
    const size_t num_plaintext_bytes =
            json_data[JSONParser::NUM_PLAINTEXT_BYTES].asUInt64();
    const size_t num_ciphertext_bytes =
            json_data[JSONParser::NUM_CIPHERTEXT_BYTES].asUInt64();
    const size_t num_tweak_bytes =
            json_data[JSONParser::NUM_TWEAK_BYTES].asUInt64();
    const std::vector<uint8_t> key =
            to_vector(json_data[JSONParser::KEY]);
    const std::vector<uint8_t> tweak =
            to_vector(json_data[JSONParser::TWEAK]);
    const std::vector<uint8_t> plaintext =
            to_vector(json_data[JSONParser::PLAINTEXT]);
    const std::vector<uint8_t> ciphertext =
            to_vector(json_data[JSONParser::CIPHERTEXT]);

    DeoxysBCTestCaseContext context(num_plaintext_bytes,
                                    num_ciphertext_bytes,
                                    num_tweak_bytes,
                                    key,
                                    tweak,
                                    plaintext,
                                    ciphertext);
    return context;
}

// ---------------------------------------------------------

DeoxysBCOptTestCaseContext JSONParser::create_deoxys_bc_opt_test_case(
        const Json::Value& json_data) {
    const size_t num_plaintext_bytes =
            json_data[JSONParser::NUM_PLAINTEXT_BYTES].asUInt64();
    const size_t num_ciphertext_bytes =
            json_data[JSONParser::NUM_CIPHERTEXT_BYTES].asUInt64();
    const size_t num_tweak_bytes =
            json_data[JSONParser::NUM_TWEAK_BYTES].asUInt64();
    const uint8_t tweak_domain =
            to_uint8_t(to_vector(json_data[JSONParser::TWEAK_DOMAIN]));
    const size_t tweak_counter =
            to_uint64_t(to_vector(json_data[JSONParser::TWEAK_COUNTER]));

    const std::vector<uint8_t> key =
            to_vector(json_data[JSONParser::KEY]);
    const std::vector<uint8_t> tweak =
            to_vector(json_data[JSONParser::TWEAK]);
    const std::vector<uint8_t> plaintext =
            to_vector(json_data[JSONParser::PLAINTEXT]);
    const std::vector<uint8_t> ciphertext =
            to_vector(json_data[JSONParser::CIPHERTEXT]);

    DeoxysBCOptTestCaseContext context(num_plaintext_bytes,
                                       num_ciphertext_bytes,
                                       num_tweak_bytes,
                                       tweak_domain,
                                       tweak_counter,
                                       key,
                                       tweak,
                                       plaintext,
                                       ciphertext);
    return context;
}

// ---------------------------------------------------------

GFDoublingTestCaseContext JSONParser::create_gf_doubling_test_case(
        const Json::Value& json_data) {
    const size_t num_input_bytes =
            json_data[JSONParser::NUM_INPUT_BYTES].asUInt64();
    const size_t num_output_bytes =
            json_data[JSONParser::NUM_OUTPUT_BYTES].asUInt64();

    const std::vector<uint8_t> input =
            to_vector(json_data[JSONParser::INPUT]);
    const std::vector<uint8_t> output =
            to_vector(json_data[JSONParser::OUTPUT]);

    GFDoublingTestCaseContext context(num_input_bytes,
                                      num_output_bytes,
                                      input,
                                      output);
    return context;
}

// ---------------------------------------------------------
