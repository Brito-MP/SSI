#!/bin/bash

USER_SETUID="userssi"

# Exercício 1
touch leitor.c

cat > leitor.c <<'EOF'
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
EOF

gcc leitor.c -o leitor
ls -l leitor

# Exercício 2
sudo adduser $USER_SETUID

# Exercício 3
sudo chown $USER_SETUID leitor
sudo chown $USER_SETUID braga.txt
sudo chmod 555 leitor
sudo chmod 400 braga.txt
ls -l leitor braga.txt

# Exercício 4
./leitor braga.txt

# Exercício 5
sudo chmod u+s leitor
ls -l leitor

# Exercício 6
./leitor braga.txt

# Com setuid, o programa corre com o utilizador efetivo do dono do executável.