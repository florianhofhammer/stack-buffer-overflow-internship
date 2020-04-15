#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char globalbuff[256];

int main(int argc, char *argv[]) {
    strncpy(globalbuff, argv[1], 256);

    char buff[32];
    snprintf(buff, sizeof(buff), argv[2]);
    buff[sizeof(buff) - 1] = '\0';

    return 0;
}
