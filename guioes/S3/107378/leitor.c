#include <stdio.h>
#include <stdlib.h>

static int copy_stream(FILE *stream)
{
    int byte;

    while ((byte = fgetc(stream)) != EOF) {
        if (putchar(byte) == EOF) {
            return -1;
        }
    }

    return ferror(stream) ? -1 : 0;
}

int main(int argc, char **argv)
{
    FILE *input;

    if (argc != 2) {
        fprintf(stderr, "Uso: %s <ficheiro>\n", argv[0]);
        return EXIT_FAILURE;
    }

    input = fopen(argv[1], "r");
    if (input == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    if (copy_stream(input) != 0) {
        perror("leitura");
        fclose(input);
        return EXIT_FAILURE;
    }

    fclose(input);
    return EXIT_SUCCESS;
}
