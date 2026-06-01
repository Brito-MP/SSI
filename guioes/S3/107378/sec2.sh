#!/usr/bin/env bash
set -euo pipefail

USER_A="user107378a"
USER_B="user107378b"
USER_C="user107378c"
GROUP_ALL="grupo107378"
GROUP_PAIR="par107378"

ensure_user() {
    local name="$1"
    if ! id "$name" >/dev/null 2>&1; then
        sudo adduser --disabled-password --gecos "" "$name"
    fi
}

ensure_group() {
    local name="$1"
    if ! getent group "$name" >/dev/null; then
        sudo groupadd "$name"
    fi
}

# Exercicio 0: estado inicial relevante.
getent passwd "$USER_A" "$USER_B" "$USER_C" || true
getent group "$GROUP_ALL" "$GROUP_PAIR" || true

# Exercicios 1 e 2: utilizadores e grupos do guiao.
ensure_user "$USER_A"
ensure_user "$USER_B"
ensure_user "$USER_C"
ensure_group "$GROUP_ALL"
ensure_group "$GROUP_PAIR"

sudo usermod -aG "$GROUP_ALL" "$USER_A"
sudo usermod -aG "$GROUP_ALL" "$USER_B"
sudo usermod -aG "$GROUP_ALL" "$USER_C"
sudo usermod -aG "$GROUP_PAIR" "$USER_A"
sudo usermod -aG "$GROUP_PAIR" "$USER_B"

# Exercicio 3: confirmar as novas entradas.
getent passwd "$USER_A" "$USER_B" "$USER_C"
getent group "$GROUP_ALL" "$GROUP_PAIR"

# Exercicios 4 e 5: posse e leitura de um ficheiro protegido.
printf "Conteudo reservado de Braga\n" > braga.txt
sudo chown "$USER_A:$USER_A" braga.txt
sudo chmod 400 braga.txt
ls -l braga.txt
cat braga.txt || true

# Exercicios 6 a 9: comandos executados como outro utilizador.
mkdir -p dir2
chmod u=rwx,g=,o= dir2
sudo -u "$USER_A" id
sudo -u "$USER_A" groups
sudo -u "$USER_A" cat braga.txt
sudo -u "$USER_A" bash -c 'cd dir2 && pwd' || true

# A leitura resulta para o dono do ficheiro. A entrada em dir2 falha para quem
# nao for dono nem tiver permissao de execucao na diretoria.
