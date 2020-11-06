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

To generate the binaries (see the [Docs](https://aflplus.plus/docs/env_variables/)):
```
CC=afl-clang-fast AFL_HARDEN=1 make
```

To use **libtokencap** to generate dictionaries, use the `AFL_NO_BUILTIN=1` flag:
```
CC=afl-clang-fast AFL_HARDEN=1 AFL_NO_BUILTIN=1 make 
```

## afl-fuzz
For programs that taken input directly from STDIN:
```
afl-fuzz -i <input dir> -o <output dir> <vulnerable program>
afl-fuzz -i inputs -o out ./vulnerable
```

For programs that take a file as input, use `@@` to mark where the input file name should be:
```
afl-fuzz -i <input dir> -o <output dir> <vulnerable program> @@
afl-fuzz -i inputs -o out /path/to/program @@
```

Optional flags:
| Flag       | Example                 | Explanation                                                            |
|------------|-------------------------|------------------------------------------------------------------------|
| -x <dict>  | -x my.dict              | Use dictionary                                                         |
| -m <amount>| -m none                 | Memory limit for child process                                         |
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

## Persistent Mode
Useful for fast targets, provides x2 speed boost. Example `harness.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF; // AFL testcase input
    
    // Number passed to __AFL_LOOP() is the maximum number of iterations before termination
    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN; // Length of testcase
        
        /* Main program logic here, testcase stored in buf, can be access using: 
          
          (char *) buf 
          
          For example: */
          
        xmlDocPtr doc = doc = xmlReadMemory((char *) buf, len, "noname.xml", NULL, 0);
    }

    return 0;
}
```

## Ram Disks for SSDs
```bash
mkdir /tmp/afl-ramdisk && chmod 777 /tmp/afl-ramdisk
mount -t tmpfs -o size=512M tmpfs /tmp/afl-ramdisk
cd /tmp/afl-ramdisk
```

## Corpus
* https://github.com/strongcourage/fuzzing-corpus
* https://github.com/dvyukov/go-fuzz-corpus
* Images: https://lcamtuf.coredump.cx/afl/demo/
