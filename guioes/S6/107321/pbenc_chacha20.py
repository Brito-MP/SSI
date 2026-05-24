#!/usr/bin/env python3
import getpass
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 16
ITERACOES = 480000


def uso():
    print("uso:")
    print("  python3 pbenc_chacha20.py enc <ficheiro>")
    print("  python3 pbenc_chacha20.py dec <ficheiro>")
    sys.exit(1)


def ler_passphrase():
    if sys.stdin.isatty():
        return getpass.getpass("passphrase: ").encode()
    return sys.stdin.readline().rstrip("\n").encode()


def deriva_chave(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERACOES,
    )
    return kdf.derive(passphrase)


def chacha20(chave, nonce, dados):
    cipher = Cipher(algorithms.ChaCha20(chave, nonce), mode=None)
    ctx = cipher.encryptor()
    return ctx.update(dados) + ctx.finalize()


def enc(fich):
    passphrase = ler_passphrase()
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    chave = deriva_chave(passphrase, salt)

    with open(fich, "rb") as f:
        texto = f.read()

    ctxt = chacha20(chave, nonce, texto)
    with open(fich + ".enc", "wb") as f:
        f.write(salt + nonce + ctxt)


def dec(fich):
    passphrase = ler_passphrase()
    with open(fich, "rb") as f:
        dados = f.read()

    salt = dados[:SALT_SIZE]
    nonce = dados[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ctxt = dados[SALT_SIZE + NONCE_SIZE:]
    chave = deriva_chave(passphrase, salt)

    texto = chacha20(chave, nonce, ctxt)
    with open(fich + ".dec", "wb") as f:
        f.write(texto)


def main():
    if len(sys.argv) != 3:
        uso()
    if sys.argv[1] == "enc":
        enc(sys.argv[2])
    elif sys.argv[1] == "dec":
        dec(sys.argv[2])
    else:
        uso()


if __name__ == "__main__":
    main()
