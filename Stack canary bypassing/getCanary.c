#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define QWORDNUM 20  // Number of quad words (i.e. 8 bytes) to output from the stack

void func(pid_t pid) {
    // Create a buffer and a pointer to that buffer
    uint8_t buf[8];
    uint64_t *ptr = (uint64_t *)buf;
    uint64_t i;
    ptr -= 3;

    // Fill buffer with A letters to easily find it in memory
    memset(buf, 0x41, 8);

    // Print stack content
    printf("%s process with PID %d\n", pid ? "Parent" : "Child", getpid());
    printf("    Address    |     Content     \n");
    printf("---------------------------------\n");
    for (i = 0; i < QWORDNUM; i++) {
        printf("%p | %.16lx\n", ptr, *ptr);
        ptr++;
    }
    printf("\n");
}

int main(int argc, char *argv) {
    // Create a buffer
    uint8_t buf[8];
    pid_t pid;

    // Fill buffer with B letters to easily find it in memory
    memset(buf, 0x42, 8);

    // Fork => two processes from here on
    pid = fork();
    if (pid > 0) {
        // Parent process
        waitpid(pid, NULL, 0);
    }
    func(pid);
    return 0;
}
