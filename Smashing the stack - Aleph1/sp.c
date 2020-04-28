#include <stdio.h>

unsigned long get_sp(void) {
    unsigned long result;
    asm("movl %%esp,%0"
        : "=g"(result));
    return result;
}

void main() {
    printf("0x%lx\n", get_sp());
}
