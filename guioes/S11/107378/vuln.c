#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void zona_privilegiada(void)
{
    puts("[!] Funcao sensivel atingida.");
    puts("[!] Num caso real, este desvio poderia executar codigo escolhido.");
    exit(EXIT_SUCCESS);
}

static void processa_argumento(const char *entrada)
{
    char local[64];

    printf("[*] Endereco do buffer: %p\n", (void *)local);
    printf("[*] Endereco da funcao sensivel: %p\n", (void *)zona_privilegiada);

    strcpy(local, entrada);
    printf("[*] Entrada recebida: %s\n", local);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <texto>\n", argv[0]);
        return EXIT_FAILURE;
    }

    puts("[*] Programa vulneravel a overflow na stack.");
    processa_argumento(argv[1]);
    puts("[*] Terminacao normal.");
    return EXIT_SUCCESS;
}
