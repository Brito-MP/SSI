#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void zona_privilegiada(void)
{
    puts("[!] Funcao sensivel atingida.");
    puts("[!] Num caso real, este desvio poderia executar codigo escolhido.");
    exit(EXIT_SUCCESS);
}

static int processa_argumento(const char *entrada)
{
    char local[64];
    size_t tamanho = strlen(entrada);

    printf("[*] Endereco do buffer: %p\n", (void *)local);
    printf("[*] Endereco da funcao sensivel: %p\n", (void *)zona_privilegiada);

    if (tamanho >= sizeof(local)) {
        fprintf(stderr, "[!] Entrada demasiado longa: maximo %zu bytes.\n", sizeof(local) - 1);
        return -1;
    }

    snprintf(local, sizeof(local), "%s", entrada);
    printf("[*] Entrada recebida: %s\n", local);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <texto>\n", argv[0]);
        return EXIT_FAILURE;
    }

    puts("[*] Programa com validacao de tamanho.");
    if (processa_argumento(argv[1]) != 0) {
        return EXIT_FAILURE;
    }
    puts("[*] Terminacao normal.");
    return EXIT_SUCCESS;
}
