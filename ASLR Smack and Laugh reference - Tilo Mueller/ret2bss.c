#include <string.h>

char globalbuf[256];

void function(char *s) {
    char localbuf[256];
    strcpy(localbuf, s);
    strcpy(globalbuf, localbuf);
}

int main(int argc, char *argv[]) {
    function(argv[1]);
    return 0;
}
