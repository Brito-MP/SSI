#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void) {
    int dfd;
    char *argv[] = {"/bin/sh", NULL};

    dfd = open("/root", O_RDONLY);
    if (dfd < 0) {
        perror("open");
        return 1;
    }

    printf("fd da diretoria /root: %d\n", dfd);

    if (mkdir("/root/backupssi", 0700) < 0) {
        perror("mkdir");
    }

    close(dfd);

    if (setuid(getuid()) < 0) {
        perror("setuid");
        return 1;
    }

    execve(argv[0], argv, NULL);
    perror("execve");
    return 1;
}
