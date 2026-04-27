#!/bin/bash

USER1="ssiuser1"
USER2="ssiuser2"
USER3="ssiuser3"

# Exercício 0
cat /etc/passwd
cat /etc/group

# Exercício 1
sudo adduser $USER1
sudo adduser $USER2
sudo adduser $USER3

# Exercício 2
sudo groupadd grupo-ssi
sudo groupadd par-ssi

sudo usermod -aG grupo-ssi $USER1
sudo usermod -aG grupo-ssi $USER2
sudo usermod -aG grupo-ssi $USER3

sudo usermod -aG par-ssi $USER1
sudo usermod -aG par-ssi $USER2

# Exercício 3
cat /etc/passwd
cat /etc/group

# Aparecem novos utilizadores em /etc/passwd e novos grupos em /etc/group.

# Exercício 4
sudo chown $USER1 braga.txt
ls -l braga.txt

# Exercício 5
cat braga.txt

# Exercício 6
echo "Sessão simulada com sudo -u $USER1"

# Exercício 7
sudo -u $USER1 id
sudo -u $USER1 groups

# Mostra o UID, GID e grupos do utilizador escolhido.

# Exercício 8
sudo -u $USER1 cat braga.txt

# O utilizador consegue ler porque passou a ser dono do ficheiro.

# Exercício 9
sudo -u $USER1 bash -c "cd dir2 && pwd"

# Só o dono da diretoria consegue entrar, porque group e other não têm execução.