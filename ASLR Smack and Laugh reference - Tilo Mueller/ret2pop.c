#include <string.h>

int function(int x, char *s) {
    char buf[256];
    strcpy(buf, s);

    return x;
}

int main(int argc, char *argv[]) {
    function(64, argv[1]);
    return 0;
}
