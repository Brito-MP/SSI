#include <stdio.h>

int main(int argc, char *argv[]) {
    FILE *f;
    int ch;

    if (argc != 2) {
        printf("Uso: %s <ficheiro>\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "r");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }

    while ((ch = fgetc(f)) != EOF) {
        putchar(ch);
    }

    fclose(f);
    return 0;
}
