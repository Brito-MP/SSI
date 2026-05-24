#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_SIZE = 32
NONCE_SIZE = 16


def uso():
    print("uso:")
    print("  python3 cfich_aes_ctr.py setup <ficheiro_chave>")
    print("  python3 cfich_aes_ctr.py enc <ficheiro> <ficheiro_chave>")
    print("  python3 cfich_aes_ctr.py dec <ficheiro> <ficheiro_chave>")
    sys.exit(1)


def ler_chave(nome):
    with open(nome, "rb") as f:
        chave = f.read()
    if len(chave) != KEY_SIZE:
        raise ValueError("a chave deve ter 32 bytes")
    return chave


def aplicar(chave, nonce, dados):
    cipher = Cipher(algorithms.AES(chave), modes.CTR(nonce))
    ctx = cipher.encryptor()
    return ctx.update(dados) + ctx.finalize()


def setup(fkey):
    with open(fkey, "wb") as f:
        f.write(os.urandom(KEY_SIZE))


def enc(fich, fkey):
    chave = ler_chave(fkey)
    nonce = os.urandom(NONCE_SIZE)
    with open(fich, "rb") as f:
        texto = f.read()
    ctxt = aplicar(chave, nonce, texto)
    with open(fich + ".enc", "wb") as f:
        f.write(nonce + ctxt)


def dec(fich, fkey):
    chave = ler_chave(fkey)
    with open(fich, "rb") as f:
        dados = f.read()
    nonce = dados[:NONCE_SIZE]
    ctxt = dados[NONCE_SIZE:]
    texto = aplicar(chave, nonce, ctxt)
    with open(fich + ".dec", "wb") as f:
        f.write(texto)


def main():
    if len(sys.argv) < 3:
        uso()
    op = sys.argv[1]
    if op == "setup" and len(sys.argv) == 3:
        setup(sys.argv[2])
    elif op == "enc" and len(sys.argv) == 4:
        enc(sys.argv[2], sys.argv[3])
    elif op == "dec" and len(sys.argv) == 4:
        dec(sys.argv[2], sys.argv[3])
    else:
        uso()


if __name__ == "__main__":
    main()
