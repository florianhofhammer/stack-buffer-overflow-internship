#include <string.h>

void function(char *args) {
    char buffer[4096];
    strcpy(buffer, args);
}

int main(int argc, char *argv[]) {
    function(argv[1]);
    return 0;
}
