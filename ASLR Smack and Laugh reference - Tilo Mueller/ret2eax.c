#include <string.h>

void function(char *s) {
    char buf[256];
    strcpy(buf, s);
}

int main(int argc, char *argv[]) {
    function(argv[1]);
    return 0;
}
