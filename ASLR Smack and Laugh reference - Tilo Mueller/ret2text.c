#include <unistd.h>
#include <stdio.h>
#include <string.h>

void public(char *s) {
    char buff[12];
    strcpy(buff, s);
    printf("Public function\n");
}

void secret(void) {
    printf("Secret function\n");
}

int main(int argc, char *argv[]) {
    if (geteuid() == 0) {
        // Root user is allowed to access the secret function
        secret();
    } else {
        // All other users may just access the public function
        public(argv[1]);
    }
    return 0;
}
