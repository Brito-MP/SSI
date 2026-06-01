#!/usr/bin/env python3
import os
import sys


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def grava_chave(tamanho, destino):
    if tamanho < 0:
        raise ValueError("tamanho invalido")
    with open(destino, "wb") as output:
        output.write(os.urandom(tamanho))


def aplica(ficheiro, ficheiro_chave, sufixo):
    with open(ficheiro, "rb") as input_file:
        dados = input_file.read()
    with open(ficheiro_chave, "rb") as key_file:
        chave = key_file.read()

    if len(chave) < len(dados):
        raise ValueError("chave demasiado curta")

    with open(ficheiro + sufixo, "wb") as output:
        output.write(xor_bytes(dados, chave))


def main():
    if len(sys.argv) != 4:
        return
    try:
        if sys.argv[1] == "setup":
            grava_chave(int(sys.argv[2]), sys.argv[3])
        elif sys.argv[1] == "enc":
            aplica(sys.argv[2], sys.argv[3], ".enc")
        elif sys.argv[1] == "dec":
            aplica(sys.argv[2], sys.argv[3], ".dec")
    except (OSError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
