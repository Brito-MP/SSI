#!/usr/bin/env python3
import getpass
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 16


def usage():
    print("uso: python3 pbenc_chacha20.py enc <fich>")
    print("uso: python3 pbenc_chacha20.py dec <fich>")
    sys.exit(1)


def passphrase():
    if sys.stdin.isatty():
        return getpass.getpass("passphrase: ").encode()
    return sys.stdin.readline().rstrip("\n").encode()


def derive(password, salt):
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2 ** 14, r=8, p=1)
    return kdf.derive(password)


def chacha(key, nonce, data):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    ctx = cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def encrypt(path):
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive(passphrase(), salt)
    with open(path, "rb") as input_file:
        plaintext = input_file.read()
    with open(path + ".enc", "wb") as output:
        output.write(salt + nonce + chacha(key, nonce, plaintext))


def decrypt(path):
    with open(path, "rb") as input_file:
        packed = input_file.read()
    if len(packed) < SALT_LEN + NONCE_LEN:
        raise ValueError("ficheiro cifrado invalido")
    salt = packed[:SALT_LEN]
    nonce = packed[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = packed[SALT_LEN + NONCE_LEN:]
    key = derive(passphrase(), salt)
    with open(path + ".dec", "wb") as output:
        output.write(chacha(key, nonce, ciphertext))


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "enc":
            encrypt(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "dec":
            decrypt(sys.argv[2])
        else:
            usage()
    except (OSError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
