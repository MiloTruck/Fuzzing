# AFL Notes

## Compiling C code into binaries:
Makefile, same it with the name `Makefile`:
```
# Enable debugging and suppress pesky warnings
CFLAGS ?= -g -w

all:    vulnerable

clean:
        rm -f vulnerable

vulnerable: vulnerable.c
        ${CC} ${CFLAGS} vulnerable.c -o vulnerable
```

To generate the binaries:
```
CC=afl-clang-fast AFL_HARDEN=1 make
```

To use **libtokencap** to generate dictionaries, use the `AFL_NO_BUILTIN=1` flag:
```
CC=afl-clang-fast AFL_HARDEN=1 AFL_NO_BUILTIN=1 make 
```

## afl-fuzz
`afl-fuzz` syntax:
```
afl-fuzz -i <input dir> -o <output dir> <vulnerable program>
afl-fuzz -i inputs -o out ./vulnerable
```

Optional flags:
| Flag       | Example                 | Explanation                                                            |
|------------|-------------------------|------------------------------------------------------------------------|
| -x <dict>  | -x my.dict              | Use dictionary                                                         |
| -M/-S <id> | -M fuzzer01             | Parallel fuzzing, refer to https://aflplus.plus/docs/parallel_fuzzing/ |

Dictionaries can be found:
* In the `AFLplusplus/dictionaries` directory.
* [LibFuzzer's Collection](https://chromium.googlesource.com/chromium/src/+/master/testing/libfuzzer/fuzzers/dicts)

## libtokencap
Can be found in `AFLplusplus/libtokencap`

Load the library via LD_PRELOAD. The optimal usage
pattern is to allow afl-fuzz to fuzz normally for a while and build up a corpus,
and then fire off the target binary, with libtokencap.so loaded, on every file
found by AFL in that earlier run. This demonstrates the basic principle:
```bash
export AFL_TOKEN_FILE=$PWD/temp_output.txt
touch $PWD/temp_output.txt

for i in <out_dir>/queue/id*; do
    cat $i | LD_PRELOAD= /mnt/c/Users/brand/Tools/AFLplusplus/libtokencap.so /path/to/target/program [...params]
done

sort -u temp_output.txt > afl_dictionary.dict
```
