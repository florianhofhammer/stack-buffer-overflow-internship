#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 2323

void echo(int fd) {
    char buffer[256];
    // Output stack information to check exploit correctness (does only work when compiled without compiler optimizations!)
    uint64_t *canary = (uint64_t *)buffer + 33;
    fprintf(stderr, "Stack canary (little endian): 0x%.16lx\nSaved frame pointer (little endian): 0x%.16lx\nReturn address (little endian): 0x%.16lx\n", *canary, *(canary + 1), *(canary + 2));
    ssize_t n;
    write(fd, "> ", 2);
    n = read(fd, buffer, 1024);  // Buffer overflow vulnerability is here
    write(fd, buffer, n);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in servaddr;
    int sock, fd;
    ssize_t n;
    pid_t pid;

    // Output stack canary on the server prompt for easy comparison with the leaked value
    uint64_t *canary = (uint64_t *)&servaddr + 3;
    printf("Stack canary (little endian): 0x%.16lx\n", *canary);

    // Ignore SIGCHLD signal to prevent zombie child processes
    signal(SIGCHLD, SIG_IGN);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (errno == EADDRINUSE) {
        fprintf(stderr, "Port occupied\n");
        exit(EXIT_FAILURE);
    }
    listen(sock, 1024);

    while (1) {
        fd = accept(sock, NULL, NULL);
        if ((pid = fork()) == 0) {
            // Child process echoes the input ....
            echo(fd);
            write(fd, "OK\n", 3);
            close(fd);
            // ... and then exits
            exit(EXIT_SUCCESS);
        } else {
            // Parent process continues in the infinite loop and waits for next connection
            close(fd);
        }
    }
}
