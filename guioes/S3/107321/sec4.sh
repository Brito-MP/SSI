#!/bin/bash

U="aluno1"

# preparação
sudo apt install -y acl

# 1
getfacl porto.txt

# 2
sudo setfacl -m g:grupo-ssi:w porto.txt

# 3
getfacl porto.txt
# Em relação ao resultado anterior, aparece uma entrada extra para grupo-ssi
# com permissão de escrita no ficheiro porto.txt.

# 4
sudo -u $U bash -c 'echo "linha acrescentada por um utilizador do grupo" >> porto.txt'
sudo -u $U cat porto.txt
# A escrita é possível por causa da ACL dada ao grupo grupo-ssi. A leitura pode
# falhar, porque a ACL atribuída foi apenas de escrita e não de leitura.
