#!/bin/bash

U1="aluno1"
U2="aluno2"
U3="aluno3"

# 0
cat /etc/passwd
cat /etc/group

# 1
sudo adduser --disabled-password --gecos "" $U1
sudo adduser --disabled-password --gecos "" $U2
sudo adduser --disabled-password --gecos "" $U3

# 2
sudo groupadd grupo-ssi
sudo groupadd par-ssi

sudo usermod -aG grupo-ssi $U1
sudo usermod -aG grupo-ssi $U2
sudo usermod -aG grupo-ssi $U3

sudo usermod -aG par-ssi $U1
sudo usermod -aG par-ssi $U2

# 3
cat /etc/passwd
cat /etc/group
# Foram adicionadas novas linhas aos ficheiros, correspondentes aos utilizadores
# criados e aos grupos grupo-ssi e par-ssi.

# 4
sudo chown $U1 braga.txt
ls -l braga.txt

# 5
cat braga.txt

# 6
# Em vez de abrir uma sessão interativa com su, os comandos seguintes são
# executados como o utilizador escolhido.

# 7
sudo -u $U1 id
sudo -u $U1 groups
# O id mostra o UID/GID do utilizador. O comando groups mostra também os grupos
# secundários, incluindo grupo-ssi e par-ssi.

# 8
sudo -u $U1 cat braga.txt
# Como o ficheiro braga.txt passou a pertencer ao utilizador escolhido,
# ele consegue ler o seu conteúdo.

# 9
sudo -u $U1 bash -c 'cd dir2 && pwd'
# O acesso a uma diretoria exige permissão de execução no caminho. Se o utilizador
# não for o dono e não tiver x, o cd falha com permissão negada.
