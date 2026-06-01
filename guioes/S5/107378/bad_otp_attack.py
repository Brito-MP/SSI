#!/usr/bin/env python3
import random
import sys


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def le_binario(path):
    with open(path, "rb") as input_file:
        return input_file.read()


def escreve_possivel_texto(dados):
    try:
        print(dados.decode("utf-8"), end="")
    except UnicodeDecodeError:
        print(dados.hex())


def ataque_seed(tamanho_chave, ficheiro_cifra, palavras):
    cifra = le_binario(ficheiro_cifra)
    pistas = [palavra.encode() for palavra in palavras]

    for seed in range(1 << 16):
        rng = random.Random(seed.to_bytes(2, "big"))
        chave = rng.randbytes(tamanho_chave)
        claro = xor_bytes(cifra, chave)
        if any(pista in claro for pista in pistas):
            escreve_possivel_texto(claro)
            return


def ataque_reutilizacao(ficheiro_cifra_1, ficheiro_cifra_2, conhecido=None):
    c1 = le_binario(ficheiro_cifra_1)
    c2 = le_binario(ficheiro_cifra_2)
    relacao = xor_bytes(c1, c2)

    if conhecido is None:
        print(relacao.hex())
        return

    conhecido_bytes = conhecido.encode()
    recuperado = xor_bytes(relacao, conhecido_bytes)
    escreve_possivel_texto(recuperado)


def main():
    if len(sys.argv) < 3:
        return

    try:
        tamanho = int(sys.argv[1])
    except ValueError:
        if len(sys.argv) == 3:
            ataque_reutilizacao(sys.argv[1], sys.argv[2])
        elif len(sys.argv) == 4:
            ataque_reutilizacao(sys.argv[1], sys.argv[2], sys.argv[3])
        return

    if len(sys.argv) >= 4:
        ataque_seed(tamanho, sys.argv[2], sys.argv[3:])


if __name__ == "__main__":
    main()
