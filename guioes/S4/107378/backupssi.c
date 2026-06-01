#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    char *const shell[] = {"/bin/sh", NULL};
    int root_dir;

    root_dir = open("/root", O_RDONLY | O_DIRECTORY);
    if (root_dir < 0) {
        perror("open /root");
        return EXIT_FAILURE;
    }

    printf("Descritor aberto para /root: %d\n", root_dir);

    if (mkdir("/root/backupssi", 0700) < 0) {
        perror("mkdir /root/backupssi");
    }

    if (setuid(getuid()) < 0) {
        perror("setuid");
        return EXIT_FAILURE;
    }

    execve(shell[0], shell, NULL);
    perror("execve");
    return EXIT_FAILURE;
}
