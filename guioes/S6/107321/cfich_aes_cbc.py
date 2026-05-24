#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

KEY_SIZE = 32
IV_SIZE = 16
BLOCK_BITS = 128


def uso():
    print("uso:")
    print("  python3 cfich_aes_cbc.py setup <ficheiro_chave>")
    print("  python3 cfich_aes_cbc.py enc <ficheiro> <ficheiro_chave>")
    print("  python3 cfich_aes_cbc.py dec <ficheiro> <ficheiro_chave>")
    sys.exit(1)


def ler_chave(nome):
    with open(nome, "rb") as f:
        chave = f.read()
    if len(chave) != KEY_SIZE:
        raise ValueError("a chave deve ter 32 bytes")
    return chave


def setup(fkey):
    with open(fkey, "wb") as f:
        f.write(os.urandom(KEY_SIZE))


def enc(fich, fkey):
    chave = ler_chave(fkey)
    iv = os.urandom(IV_SIZE)
    with open(fich, "rb") as f:
        texto = f.read()

    padder = padding.PKCS7(BLOCK_BITS).padder()
    texto_padded = padder.update(texto) + padder.finalize()

    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    ctx = cipher.encryptor()
    ctxt = ctx.update(texto_padded) + ctx.finalize()

    with open(fich + ".enc", "wb") as f:
        f.write(iv + ctxt)


def dec(fich, fkey):
    chave = ler_chave(fkey)
    with open(fich, "rb") as f:
        dados = f.read()
    iv = dados[:IV_SIZE]
    ctxt = dados[IV_SIZE:]

    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    ctx = cipher.decryptor()
    texto_padded = ctx.update(ctxt) + ctx.finalize()

    unpadder = padding.PKCS7(BLOCK_BITS).unpadder()
    texto = unpadder.update(texto_padded) + unpadder.finalize()

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
