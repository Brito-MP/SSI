#!/usr/bin/env bash
set -euo pipefail

RUN_AS="user107378c"

if ! id "$RUN_AS" >/dev/null 2>&1; then
    sudo adduser --disabled-password --gecos "" "$RUN_AS"
fi

gcc -Wall -Wextra -g leitor.c -o leitor
printf "Segredo lido atraves de setuid\n" > braga.txt

sudo chown "$RUN_AS:$RUN_AS" leitor braga.txt
sudo chmod 555 leitor
sudo chmod 400 braga.txt
ls -l leitor braga.txt

./leitor braga.txt || true

sudo chmod u+s leitor
ls -l leitor
./leitor braga.txt

# Sem setuid, o programa corre com o utilizador real. Com setuid, o utilizador
# efetivo passa a ser o dono do executavel, permitindo ler o ficheiro dele.
