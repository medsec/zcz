# Reference and Optimized C/C++ Implementations of ZCZ with Deoxys-BC-128-384.

## Contents

- `test-zcz-ref.c`
  Tests ZCZ using Deoxys-BC-128-384.

- `test-zcz-opt.c`
  Tests ZCZ using Deoxys-BC-128-384.

- `test-deoxysbc-ref.c`
  Tests Deoxys-BC-128-384.

- `test-deoxysbc-opt.c`
  Tests Deoxys-BC-128-384.

- `test-gfdoubling-ref.c`
  Helper to test GF doubling.

- `test-gfdoubling-opt.c`
  Helper to test GF doubling.

  
## Disclaimer
The purpose of this repository is for reference and benchmarking only. 
The reference implementation of the AES is adopted from OpenSSL and 
uses ice-age-old lookup tables that render it potentially vulnerable to 
side-channel timing attacks.

Do NOT use this code in any production product or environment. As the code
says in nearly every header: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT 
WARRANTY OF ANY KIND,  


## Dependencies

- Google Test: Unit testing 

- JsonCPP: For reading unit testing 

- Make for compilation

- clang-format and clang-tidy if desired

- clang-sanitizers if desired

The optimized version requires available AES-NI (new instructions) that
are available on many modern processors (Intel i5 since Westmere, AMD
since Bulldozer). 

## Compilation
If make is known, run

`make'

or, mostly, it suffices to run

`test-deoxys-ref`
`test-zcz-ref`
`test-deoxys-opt`
`test-zcz-opt`
`benchmark`

For testing:

`bin/test-deoxysbc`
`bin/test-zcz-opt`
`bin/test-zcz-ref`

For benchmarking:

`bin/benchmark-deoxysbc`
`bin/benchmark-zcz`

For linting:

`make lint' for all of the following:
`make lint-opt`
`make lint-ref`
`make lint-shared`

