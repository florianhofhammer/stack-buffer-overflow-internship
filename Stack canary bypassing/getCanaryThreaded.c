#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADNUM 2  // Number of threads to create
#define QWORDNUM 10  // Number of quad words (i.e. 8 bytes) to output from the stack

pthread_mutex_t output_mutex;
pthread_t threads[THREADNUM];

void *func(void *params) {
    // Create a buffer and a pointer to that buffer
    uint8_t buf[8];
    uint64_t *ptr = (uint64_t *)buf;
    uint64_t i;
    ptr -= 3;

    // Fill buffer with A letters to easily find it in memory
    memset(buf, 0x41, 8);

    pthread_mutex_lock(&output_mutex);
    // Print stack content
    printf("Thread with thread ID %ld in process %d\n", pthread_self(), getpid());
    printf("    Address    |     Content     \n");
    printf("---------------------------------\n");
    for (i = 0; i < QWORDNUM; i++) {
        printf("%p | %.16lx\n", ptr, *ptr);
        ptr++;
    }
    printf("\n");
    pthread_mutex_unlock(&output_mutex);

    pthread_exit(NULL);
}

int main(int argc, char *argv) {
    // Create a buffer
    uint8_t buf[8];
    int i;

    // Fill buffer with B letters to easily find it in memory
    memset(buf, 0x42, 8);

    // Initialize mutex (used for output on stdout)
    pthread_mutex_init(&output_mutex, NULL);

    // Start threads
    for (i = 0; i < THREADNUM; i++) {
        pthread_create(&threads[i], NULL, *func, NULL);
    }
    // Join threads
    for (i = 0; i < THREADNUM; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
