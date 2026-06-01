#!/usr/bin/env bash
set -euo pipefail

USER_A="user107378a"
GROUP_ALL="grupo107378"

if ! command -v setfacl >/dev/null 2>&1; then
    sudo apt-get install -y acl
fi

printf "Texto base do ficheiro Porto\n" > porto.txt
if ! getent group "$GROUP_ALL" >/dev/null; then
    sudo groupadd "$GROUP_ALL"
fi
if id "$USER_A" >/dev/null 2>&1; then
    sudo usermod -aG "$GROUP_ALL" "$USER_A"
fi

getfacl porto.txt
sudo setfacl -m "g:${GROUP_ALL}:w" porto.txt
getfacl porto.txt

if id "$USER_A" >/dev/null 2>&1; then
    sudo -u "$USER_A" bash -c 'echo "Linha escrita via ACL" >> porto.txt'
    sudo -u "$USER_A" cat porto.txt || true
fi

# A ACL acrescenta permissao de escrita ao grupo sem alterar diretamente os bits
# tradicionais user/group/other do ficheiro.
