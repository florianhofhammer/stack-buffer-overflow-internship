/*
 * Taken from pages 147, 148 of Hacking: The Art of Exploitation, 2nd Edition by Jon Erickson
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *ptr;

    if (argc < 3) {
        printf("Usage: %s <environment variable> <target program name>\n", argv[0]);
        exit(0);
    }
    ptr = getenv(argv[1]);                          /* get env var location */
    ptr += (strlen(argv[0]) - strlen(argv[2])) * 2; /* adjust for program name */
    printf("%s will be at %p\n", argv[1], ptr);
}
