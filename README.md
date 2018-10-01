# Reference and Optimized C/C++ Implementations of ZCZ with Deoxys-BC-128-384.
See [BLN18] and [JNP14].

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

- cmake

- Google Test: Unit testing 

- JsonCPP: For reading unit testing 

- Make for compilation

The optimized version requires available AES-NI (new instructions) that
are available on many modern processors (Intel i5 since Westmere, AMD
since Bulldozer). 

## Compilation

If cmake is installed, run

`cmake .`

Afterwards, you can run `make <target>` with `<target>` is among:

- `test-deoxysbc-ref`
- `test-deoxysbc-opt`
- `test-gfdoubling-ref`
- `test-gfdoubling-opt`
- `test-zcz-ref`
- `test-zcz-opt`
- `benchmark-deoxysbc`
- `benchmark-zcz`

### Testing

After building, you can find testing scripts in `bin`.
You can find the test cases in the `testdata` directory.

### Benchmarking

After building, you can also find two benchmarking executables in `bin`:

- `bin/benchmark-deoxysbc`
- `bin/benchmark-zcz`

You can find a set of useful scripts for proper benchmarking. After reading
them, run with sudo privileges on your own risk.

- `scripts/disablehyperthreading.sh`
- `scripts/powerpolicy.sh ondemand`
- `scripts/turboboost.sh off`

Those can disable hyper-threading and load-based tuning of the processor
frequency to yield more reliable benchmarking results.

### Linting:

- `make lint` for all of the following:
- `make lint-opt`
- `make lint-ref`
- `make lint-shared`

# References


[BLN18] Ritam Bhaumik and Eik List and Mridul Nandi: ZCZ - Achieving n-bit SPRP Security with a Minimal Number of Tweakable-block-cipher Calls. IACR ePrint report 2018, https://eprint.iacr.org/2018/819.
[JNP14] Jérémy Jean and Ivica Nikolić and Thomas Peyrin: Tweaks and Keys for Block Ciphers: the TWEAKEY Framework. ASIACRYPT 2014, full version at https://eprint.iacr.org/2014/831.

