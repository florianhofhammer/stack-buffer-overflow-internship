#include <stdio.h>

unsigned long getEBP(void) {
    __asm__("movl %ebp, %eax");
}

void main(void) {
    printf("EBP: %lx\n", getEBP());
}
