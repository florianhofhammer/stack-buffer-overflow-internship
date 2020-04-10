#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char dest[1024];
    char src[1024];

    int cp = atoi(argv[1]);
    if (cp < 1024) {
        printf("Copy %d/%u bytes\n", cp, cp);
        memcpy(dest, src, cp);
    } else {
        printf("Input out of range\n");
    }
}
