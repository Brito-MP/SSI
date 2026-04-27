#!/bin/bash

USER1="ssiuser1"

# Preparação
sudo apt install -y acl

# Exercício 1
getfacl porto.txt

# Exercício 2
setfacl -m g:grupo-ssi:w porto.txt

# Exercício 3
getfacl porto.txt

# Aparece uma ACL para grupo-ssi com permissão de escrita.

# Exercício 4
sudo -u $USER1 bash -c 'echo "Texto escrito por utilizador do grupo grupo-ssi" >> porto.txt'
sudo -u $USER1 cat porto.txt

# O utilizador consegue escrever no ficheiro porque pertence ao grupo grupo-ssi,
# que tem permissão de escrita através da ACL.
# No entanto, não consegue ler o conteúdo do ficheiro, porque a ACL só deu escrita
