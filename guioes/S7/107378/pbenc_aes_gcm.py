#!/usr/bin/env python3
import getpass
import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LEN = 16
NONCE_LEN = 12
ITERATIONS = 260000


def usage():
    print("uso: python3 pbenc_aes_gcm.py enc <fich>")
    print("uso: python3 pbenc_aes_gcm.py dec <fich>")
    sys.exit(1)


def passphrase():
    if sys.stdin.isatty():
        return getpass.getpass("passphrase: ").encode()
    return sys.stdin.readline().rstrip("\n").encode()


def derive(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password)


def encrypt(path):
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive(passphrase(), salt)
    with open(path, "rb") as input_file:
        plaintext = input_file.read()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    with open(path + ".enc", "wb") as output:
        output.write(salt + nonce + ciphertext)


def decrypt(path):
    with open(path, "rb") as input_file:
        packed = input_file.read()
    if len(packed) < SALT_LEN + NONCE_LEN + 16:
        raise ValueError("ficheiro cifrado invalido")
    salt = packed[:SALT_LEN]
    nonce = packed[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = packed[SALT_LEN + NONCE_LEN:]
    plaintext = AESGCM(derive(passphrase(), salt)).decrypt(nonce, ciphertext, None)
    with open(path + ".dec", "wb") as output:
        output.write(plaintext)


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
