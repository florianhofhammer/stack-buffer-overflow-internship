#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void function(char *s) {
    printf("%s\n", s);
    system("echo Inside function");
}

int main(int argc, char *argv[]) {
    void (*ptr)(char *s);
    ptr = &function;

    char buff[64];
    strcpy(buff, argv[1]);

    (*ptr)(argv[2]);

    return 0;
}
