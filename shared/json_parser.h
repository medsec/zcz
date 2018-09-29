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
#ifndef _JSON_PARSER_H_
#define _JSON_PARSER_H_

// ---------------------------------------------------------

#include <json/json.h>

#include <string>

#include "deoxysbc_test_case_context.h"
#include "deoxysbc_opt_test_case_context.h"
#include "gf_doubling_test_case_context.h"
#include "zcz_test_case_context.h"


// ----------------------------------------------------------

/**
 * Helper class that parses test case parameters from JSON files so our
 * test cases are cleaner and tests can be added easily.
 */
class JSONParser {
 public:
    JSONParser() = default;

    /**
     * Given a path to a JSON file, tries to open it and parse its content.
     * @return The data of the given JSON file as a dict object.
     */
    Json::Value parse(const std::string& path);

    ZCZTestCaseContext create_zcz_test_case(const Json::Value &json_data);

    DeoxysBCTestCaseContext create_deoxys_bc_test_case(
        const Json::Value& json_data);

    DeoxysBCOptTestCaseContext create_deoxys_bc_opt_test_case(
        const Json::Value& json_data);

    GFDoublingTestCaseContext create_gf_doubling_test_case(
        const Json::Value& json_data);

 private:
    static const char KEY[];
    static const char PLAINTEXT[];
    static const char CIPHERTEXT[];
    static const char TWEAK[];
    static const char NUM_PLAINTEXT_BYTES[];
    static const char NUM_CIPHERTEXT_BYTES[];
    static const char NUM_TWEAK_BYTES[];
    static const char TWEAK_DOMAIN[];
    static const char TWEAK_COUNTER[];

    static const char INPUT[];
    static const char OUTPUT[];
    static const char NUM_INPUT_BYTES[];
    static const char NUM_OUTPUT_BYTES[];
};

// ----------------------------------------------------------

#endif  // _JSON_PARSER_H_
