#include <stdio.h>
#include <string.h>

void secret(void) {
    printf("Reached secret function\n!");
}

int main(int argc, char *argv[]) {
    char bsize = 64;
    char buff[bsize];
    char isize = strlen(argv[1]);

    if (isize < bsize) {
        printf("Copy %d byte\n", isize);
        strcpy(buff, argv[1]);
    } else {
        printf("Input out of size\n");
    }

    return 0;
}
