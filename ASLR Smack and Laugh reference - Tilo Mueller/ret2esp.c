#include <string.h>

void function(char *s) {
    char buf[256];
    strcpy(buf, s);
}

int main(int argc, char *argv[]) {
    int j = 58623;
    function(argv[1]);
}
