#include <string.h>

void function(char *s) {
    char buffer[256];
    strcpy(buffer, s);
}

int main(int argc, char *argv[]) {
    int no = 1;
    int *ptr = &no;
    function(argv[1]);
}
