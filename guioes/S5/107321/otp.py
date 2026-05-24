#!/usr/bin/env python3
import os
import sys

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def setup(nbytes, fkey):
    with open(fkey, "wb") as f:
        f.write(os.urandom(nbytes))

def aplica(fich, fkey, sufixo):
    with open(fich, "rb") as f:
        dados = f.read()

    with open(fkey, "rb") as f:
        chave = f.read()

    if len(chave) < len(dados):
        print("erro: chave demasiado curta")
        return

    with open(fich + sufixo, "wb") as f:
        f.write(xor_bytes(dados, chave))

def main():
    if len(sys.argv) != 4:
        return

    op = sys.argv[1]

    if op == "setup":
        setup(int(sys.argv[2]), sys.argv[3])
    elif op == "enc":
        aplica(sys.argv[2], sys.argv[3], ".enc")
    elif op == "dec":
        aplica(sys.argv[2], sys.argv[3], ".dec")

if __name__ == "__main__":
    main()
