#include <string.h>

char globalbuf[256] = "Some random string forcing the compiler to put this buffer into .data instead of .bss\n";

void function(char *s) {
    char localbuf[256];
    strcpy(localbuf, s);
    strcpy(globalbuf, localbuf);
}

int main(int argc, char *argv[]) {
    function(argv[1]);
    return 0;
}
