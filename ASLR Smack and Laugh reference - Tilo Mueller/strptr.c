#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    char input[256];
    char *conf = "test -f ~/.progrc";
    char *license = "THIS SOFTWARE IS ...";

    puts(license);
    strcpy(input, argv[1]);

    if (system(conf)) {
        puts("Missing .progrc");
    }

    return 0;
}
