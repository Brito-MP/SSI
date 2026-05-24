#!/bin/bash

UTIL="userssi"

# 1
gcc leitor.c -o leitor
ls -l leitor

# 2
sudo adduser --disabled-password --gecos "" $UTIL

# 3
sudo chown $UTIL:$UTIL leitor
sudo chown $UTIL:$UTIL braga.txt
sudo chmod 555 leitor
sudo chmod 400 braga.txt
ls -l leitor braga.txt

# 4
./leitor braga.txt

# 5
sudo chmod u+s leitor
ls -l leitor

# 6
./leitor braga.txt
# Depois de ativar o setuid, o executável corre com o utilizador efetivo igual
# ao dono do ficheiro. Como o dono é userssi, o programa consegue ler braga.txt.
