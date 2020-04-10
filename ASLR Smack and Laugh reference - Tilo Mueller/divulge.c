#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

int listenfd, connfd;

void function(char *s) {
    char readbuf[256], writebuf[256];
    strcpy(readbuf, s);
    sprintf(writebuf, readbuf);
    write(connfd, writebuf, strlen(writebuf));
}

int main(int argc, char *argv[]) {
    char line[1024];
    struct sockaddr_in servaddr;
    ssize_t n;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(7776);

    bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    listen(listenfd, 1024);

    while (1) {
        connfd = accept(listenfd, NULL, NULL);
        write(connfd, "> ", 2);
        n = read(connfd, line, sizeof(line) - 1);
        line[n] = 0;
        function(line);
        close(connfd);
    }
}
