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
