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
| -Q         | None                    | QEMU Mode for binary-only fuzzing                                      |
| -M/-S <id> | -M fuzzer01             | Parallel fuzzing, refer to [Parallel Fuzzing Docs](https://aflplus.plus/docs/parallel_fuzzing/) |

Dictionaries can be found:
* In the `AFLplusplus/dictionaries` directory.
* [LibFuzzer's Collection](https://chromium.googlesource.com/chromium/src/+/master/testing/libfuzzer/fuzzers/dicts)

## Persistent Mode and Deferred Fork-server
Find a location in code where cloning can take place. It should be before:
* Creation of threads or child processes
* Initialization of timers
* Creation of temporary files, network sockets
* Any access to fuzzed input, including reading its metadata

Add the code below in an appropriate location in the harness:
```c
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
```

Persistent mode can be utilized with the code structure below:
```c
  while (__AFL_LOOP(1000)) {

    /* Read input data. */
    /* Call library code to be fuzzed. */
    /* Reset state. */

  }

  /* Exit normally */
 ```

Example `harness.c`:
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
    
    /* Initialize variables to be used */
    char buf[100];
    
    // Number passed to __AFL_LOOP() is the maximum number of iterations before termination
    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN; // Length of testcase
        
        /* Main program logic here 
           STEP 1: Re-initialize variables */
        
        memset(buf, 0, sizeof(buf));
    }

    return 0;
}
```

## Binary-only Fuzzing (QEMU)
Run `afl-fuzz` with the `-Q` flag, which will enable QEMU mode.

Environment variables can be set with the following before running `afl-fuzz`:
```bash
export AFL_QEMU_PERSISTENT_ADDR=
export AFL_QEMU_PERSISTENT_RET=
export AFL_QEMU_PERSISTENT_GPR=1
afl-fuzz -Q -m none -i <input dir> -o <output dir> <vulnerable program> @@
```

Persistent Mode environment variables [Persistent Mode Docs](https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.persistent.md):
| Environment Variable     | Explanation   |
|--------------------------|---------------|
| AFL_QEMU_PERSISTENT_ADDR | START Address |
| AFL_QEMU_PERSISTENT_RET  | RET Address   |
| AFL_QEMU_PERSISTENT_RETADDR_OFFSET  | RET Offset if RET Address not set   |
| AFL_QEMU_PERSISTENT_GPR  | Restore registers, set to 1   |
| AFL_QEMU_PERSISTENT_CNT  | Loop counter, should be between 100 and 10000|

Documentation
* [QEMU Mode Docs](https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.md) 

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
