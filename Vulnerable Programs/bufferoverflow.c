#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv){
    int SHOULD_NOT_CHANGE = 0xdeadbeef;
    char buffer[64];

    gets(buffer);

    if (SHOULD_NOT_CHANGE == 0xdeadbeef) {
        printf("Value of SHOULD_NOT_CHANGE: 0x%08x\n", SHOULD_NOT_CHANGE);
        printf("Program exited safely.\n");
    } else {
        printf("Value of SHOULD_NOT_CHANGE: 0x%08x\n", SHOULD_NOT_CHANGE);
        printf("Success!\n");
    }
}