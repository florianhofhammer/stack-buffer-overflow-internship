#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void function(void) {
    system("Some random command");
}

int main(int argc, char *argv[]) {
    char *ptr, array[8];
    ptr = array;

    strcpy(ptr, argv[1]);
    printf("Array has %s at %p\n", ptr, ptr);
    strcpy(ptr, argv[2]);
    printf("Array has %s at %p\n", ptr, ptr);

    return 0;
}
