# ----------------------------------------------------------
# Common
# ----------------------------------------------------------

cmake_minimum_required(VERSION 2.8.12 FATAL_ERROR)

# ----------------------------------------------------------
# Project variables and paths
# ----------------------------------------------------------

# Project name
project(zcz)

# Store variables
set(PROJECT_CHECK_RESULTS_DIR check)
set(PROJECT_REF_DIR ref)
set(PROJECT_OPT_DIR opt)
set(PROJECT_SHARED_DIR shared)
set(PROJECT_TESTS_DIR tests)
set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(INCLUDE_DIRECTORIES ${PROJECT_SHARED_DIR})
set(CMAKE_CXX_STANDARD 14)


# Stores all executables in src folder into variable SOURCES
file(GLOB REF_SOURCES "${PROJECT_REF_DIR}/*.c" "${PROJECT_REF_DIR}/*.h")
file(GLOB OPT_SOURCES "${PROJECT_OPT_DIR}/*.c" "${PROJECT_OPT_DIR}/*.h")
file(GLOB SHARED_SOURCES "${PROJECT_SHARED_DIR}/*.c" "${PROJECT_SHARED_DIR}/*.h" "${PROJECT_SHARED_DIR}/json_parser.cpp" "${PROJECT_SHARED_DIR}/memutils.cpp")
file(GLOB SHARED_SOURCES_WO_UTILS "${PROJECT_SHARED_DIR}/benchmark.c" "${PROJECT_SHARED_DIR}/json_parser.cpp" "${PROJECT_SHARED_DIR}/memutils.cpp" "${PROJECT_SHARED_DIR}/align.h" "${PROJECT_SHARED_DIR}/benchmark.h" "${PROJECT_SHARED_DIR}/deoxysbc_opt_test_case_context.h" "${PROJECT_SHARED_DIR}/gf_doubling_test_case_context.h" "${PROJECT_SHARED_DIR}/json_parser.h" "${PROJECT_SHARED_DIR}/memutils.h" "${PROJECT_SHARED_DIR}/zcz_test_case_context.h")

# Stores all executables in src folder into variable SOURCES
file(GLOB TESTS "${PROJECT_TESTS_DIR}/*.cpp")

# Compile flags
SET(CMAKE_C_COMPILER clang)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall -Wextra -std=c11 -march=native")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -ggdb3 -DDEBUG -fsanitize=undefined -fsanitize=address -fsanitize=alignment -ftrapv -fno-omit-frame-pointer -fno-optimize-sibling-calls")

set(CMAKE_CXX_COMPILER "clang++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Wextra -std=c++14 -march=native")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -O3")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -ggdb3 -DDEBUG -fsanitize=undefined -fsanitize=address -fsanitize=alignment -ftrapv -fno-omit-frame-pointer -fno-optimize-sibling-calls")

# ----------------------------------------------------------
# Build Types
# ----------------------------------------------------------

if(DEBUG)
    set(CMAKE_BUILD_TYPE Debug)
else(set(CMAKE_BUILD_TYPE Release))
endif(DEBUG)

# ----------------------------------------------------------
# Libraries
# ----------------------------------------------------------

# Logging
message("Using build type ${CMAKE_BUILD_TYPE}")

# check for jsoncpp version
find_package(PkgConfig REQUIRED)

pkg_check_modules(JSONCPP jsoncpp>=1.8)

if(NOT JSONCPP_FOUND)
    pkg_check_modules(JSONCPP_OLD jsoncpp REQUIRED)
endif()

# Include GoogleTest
find_package(GTest REQUIRED)

# ----------------------------------------------------------
# Building targets of the reference implementation
# ----------------------------------------------------------

# Add executables
add_executable(test-deoxysbc-original ${PROJECT_TESTS_DIR}/test-deoxysbc-original ${REF_SOURCES} ${SHARED_SOURCES})
add_executable(test-deoxysbc-ref ${PROJECT_TESTS_DIR}/test-deoxysbc-ref ${REF_SOURCES} ${SHARED_SOURCES})
add_executable(test-gfdoubling-ref ${PROJECT_TESTS_DIR}/test-gfdoubling-ref ${REF_SOURCES} ${SHARED_SOURCES})
add_executable(test-zcz-ref ${PROJECT_TESTS_DIR}/test-zcz ${REF_SOURCES} ${SHARED_SOURCES})

# Include directories
set(REF_INCLUDE_DIRECTORIES ${PROJECT_REF_DIR} ${PROJECT_SHARED_DIR})

target_include_directories(test-deoxysbc-original PUBLIC ${REF_INCLUDE_DIRECTORIES})
target_include_directories(test-deoxysbc-ref PUBLIC ${REF_INCLUDE_DIRECTORIES})
target_include_directories(test-gfdoubling-ref PUBLIC ${REF_INCLUDE_DIRECTORIES})
target_include_directories(test-zcz-ref PUBLIC ${REF_INCLUDE_DIRECTORIES})

# Link
target_link_libraries(test-deoxysbc-original Threads::Threads gtest gtest_main jsoncpp)
target_link_libraries(test-deoxysbc-ref Threads::Threads gtest gtest_main jsoncpp)
target_link_libraries(test-zcz-ref Threads::Threads gtest gtest_main jsoncpp)
target_link_libraries(test-gfdoubling-ref Threads::Threads gtest gtest_main jsoncpp)

# ----------------------------------------------------------
# Building targets of the optimized implementation
# ----------------------------------------------------------

# Add executables
add_executable(benchmark-deoxysbc ${PROJECT_SHARED_DIR}/benchmark-deoxysbc ${OPT_SOURCES} ${SHARED_SOURCES_WO_UTILS})
add_executable(benchmark-zcz ${PROJECT_SHARED_DIR}/benchmark-zcz ${OPT_SOURCES} ${SHARED_SOURCES_WO_UTILS})
add_executable(test-deoxysbc-opt ${PROJECT_TESTS_DIR}/test-deoxysbc-opt ${OPT_SOURCES} ${SHARED_SOURCES_WO_UTILS})
add_executable(test-zcz-opt ${PROJECT_TESTS_DIR}/test-zcz ${OPT_SOURCES} ${SHARED_SOURCES_WO_UTILS})
add_executable(test-gfdoubling-opt ${PROJECT_TESTS_DIR}/test-gfdoubling-opt ${OPT_SOURCES} ${SHARED_SOURCES_WO_UTILS})

# Include directories
set(OPT_INCLUDE_DIRECTORIES ${PROJECT_OPT_DIR} ${PROJECT_SHARED_DIR})

target_include_directories(benchmark-deoxysbc PUBLIC ${OPT_INCLUDE_DIRECTORIES})
target_include_directories(benchmark-zcz PUBLIC ${OPT_INCLUDE_DIRECTORIES})
target_include_directories(test-deoxysbc-opt PUBLIC ${OPT_INCLUDE_DIRECTORIES})
target_include_directories(test-gfdoubling-opt PUBLIC ${OPT_INCLUDE_DIRECTORIES})
target_include_directories(test-zcz-opt PUBLIC ${OPT_INCLUDE_DIRECTORIES})

# Add compile options
target_compile_options(benchmark-deoxysbc PRIVATE "-DNI_ENABLED")
target_compile_options(benchmark-zcz PRIVATE "-DNI_ENABLED")
target_compile_options(test-deoxysbc-opt PRIVATE "-DNI_ENABLED")
target_compile_options(test-zcz-opt PRIVATE "-DNI_ENABLED")
target_compile_options(test-gfdoubling-opt PRIVATE "-DNI_ENABLED")

# Link
target_link_libraries(benchmark-deoxysbc jsoncpp)
target_link_libraries(benchmark-zcz jsoncpp)
target_link_libraries(test-deoxysbc-opt Threads::Threads gtest gtest_main jsoncpp)
target_link_libraries(test-zcz-opt Threads::Threads gtest gtest_main jsoncpp)
target_link_libraries(test-gfdoubling-opt Threads::Threads gtest gtest_main jsoncpp)

# ----------------------------------------------------------
# Special build targets for checking, tidying, formatting
# ----------------------------------------------------------

# Check
add_custom_target(
    lint-ref
    COMMAND cpplint
    --recursive
    --linelength=80
    --root=.
    ${PROJECT_REF_DIR}/*
)

# Check
add_custom_target(
    lint-opt
    COMMAND cpplint
    --recursive
    --linelength=80
    --root=.
    ${PROJECT_OPT_DIR}/*
)

# Check
add_custom_target(
    lint-shared
    COMMAND cpplint
    --recursive
    --linelength=80
    --root=.
    ${PROJECT_SHARED_DIR}/*
)

# # Check
# add_custom_target(
#     clang-check
#     COMMAND /usr/bin/clang-check
#     ${SOURCES}
#     --
#     -I${INCLUDE_DIRECTORIES}
#     -std=c++11
# )

# add_custom_target(
#     cppcheck
#     COMMAND cppcheck
#     --enable=warning,performance,portability,information,missingInclude
#     --std=c++11
#     --library=qt.cfg
#     --template="[{severity}][{id}] {message} {callstack} \(On {file}:{line}\)"
#     --verbose
#     --quiet
#     ${PROJECT_REF_DIR}
# )

# # Tidy
# add_custom_target(
#     clang-tidy
#     COMMAND /usr/bin/clang-tidy
#     ${SOURCES}
#     --
#     -std=c++11
#     -I${REF_SOURCES} ${SHARED_SOURCES} ${OPT_SOURCES}
# )

# # Format
# add_custom_target(
#     clang-format
#     COMMAND /usr/bin/clang-format
#     -style=file
#     -i
#     ${SOURCES}
#     -I${INCLUDE_DIRECTORIES}
# )
