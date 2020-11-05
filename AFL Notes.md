# AFL Notes

Compiling C code into binaries:
```
CC=afl-clang-fast AFL_HARDEN=1 make
```

`afl-fuzz` syntax:
```
afl-fuzz -i <input dir> -o <output dir> <vulnerable program>
afl-fuzz -i inputs -o out ./vulnerable
```

Optional flags:
| Flag     | Example     | Explanation                                                                                |
|----------|-------------|--------------------------------------------------------------------------------------------|
| -x dict  | -x my.dict  | Use dictionary                                                                             |
| -M/-S id | -M fuzzer01 | Parallel fuzzing, refer to [Parallel Fuzzing Docs](https://aflplus.plus/docs/parallel_fuzzing/) |

Dictionaries can be found:
* In the `AFLplusplus/dictionaries` directory.
* [LibFuzzer's Collection](https://chromium.googlesource.com/chromium/src/+/master/testing/libfuzzer/fuzzers/dicts)
* libtokencap, found in `AFLplusplus/libtokencap`
