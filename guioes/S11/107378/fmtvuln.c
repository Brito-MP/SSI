#include <stdio.h>
#include <stdlib.h>

static void trata_entrada(const char *entrada)
{
    unsigned long marcador = 0xcafebabeUL;

    printf("[*] Endereco do marcador: %p\n", (void *)&marcador);
    puts("[*] A imprimir entrada:");
    printf(entrada);
    putchar('\n');
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <texto>\n", argv[0]);
        return EXIT_FAILURE;
    }

    trata_entrada(argv[1]);
    puts("[*] Terminacao normal.");
    return EXIT_SUCCESS;
}
