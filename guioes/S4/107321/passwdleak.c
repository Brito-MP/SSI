#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(void) {
    int fd = open("/etc/passwd", O_WRONLY | O_APPEND);

    if (fd < 0) {
        perror("open");
        return 1;
    }

    printf("fd de /etc/passwd: %d\n", fd);

    if (setuid(getuid()) < 0) {
        perror("setuid");
        return 1;
    }

    execl("/bin/sh", "sh", NULL);
    perror("execl");
    return 1;
}
