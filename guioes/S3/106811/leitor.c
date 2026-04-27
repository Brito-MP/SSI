#include <stdio.h>

int main(int argc, char *argv[]) {
    FILE *ficheiro;
    int c;

    if (argc != 2) {
        printf("Uso: %s <ficheiro>\n", argv[0]);
        return 1;
    }

    ficheiro = fopen(argv[1], "r");

    if (ficheiro == NULL) {
        perror("Erro ao abrir ficheiro");
        return 1;
    }

    while ((c = fgetc(ficheiro)) != EOF) {
        putchar(c);
    }

    fclose(ficheiro);
    return 0;
}
