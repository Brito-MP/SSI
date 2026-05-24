#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>

int main(int argc, char **argv) {
    DIR *d;
    struct dirent *ent;
    int fd;

    if (argc != 2) {
        fprintf(stderr, "uso: %s <fd>\n", argv[0]);
        return 1;
    }

    fd = atoi(argv[1]);
    d = fdopendir(fd);
    if (d == NULL) {
        perror("fdopendir");
        return 1;
    }

    while ((ent = readdir(d)) != NULL) {
        puts(ent->d_name);
    }

    closedir(d);
    return 0;
}
