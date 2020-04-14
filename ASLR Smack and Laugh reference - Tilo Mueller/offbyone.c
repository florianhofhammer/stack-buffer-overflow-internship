#include <stdio.h>
#include <string.h>

void save(char *s) {
    char buff[256];
    strncpy(buff, s, strlen(s) + 1);
}

void function(char *s) {
    save(s);
}

int main(int argc, char *argv[]) {
    int j = 58623;
    if (strlen(argv[1]) > 256) {
        printf("Input out of size\n");
    } else {
        function(argv[1]);
    }
}
