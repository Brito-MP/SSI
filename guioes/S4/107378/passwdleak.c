#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    int fd;

    fd = open("/etc/passwd", O_WRONLY | O_APPEND);
    if (fd < 0) {
        perror("open /etc/passwd");
        return EXIT_FAILURE;
    }

    printf("Descritor de escrita em /etc/passwd: %d\n", fd);

    if (setuid(getuid()) < 0) {
        perror("setuid");
        return EXIT_FAILURE;
    }

    execl("/bin/sh", "sh", NULL);
    perror("execl");
    return EXIT_FAILURE;
}
