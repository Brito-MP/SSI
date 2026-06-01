#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

KEY_LEN = 32
NONCE_LEN = 16


def usage():
    print("uso: python3 cfich_chacha20.py setup <fkey>")
    print("uso: python3 cfich_chacha20.py enc <fich> <fkey>")
    print("uso: python3 cfich_chacha20.py dec <fich> <fkey>")
    sys.exit(1)


def read_exact_key(path):
    with open(path, "rb") as key_file:
        key = key_file.read()
    if len(key) != KEY_LEN:
        raise ValueError("a chave ChaCha20 deve ter 32 bytes")
    return key


def crypt(key, nonce, data):
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    transform = cipher.encryptor()
    return transform.update(data) + transform.finalize()


def setup(path):
    with open(path, "wb") as output:
        output.write(os.urandom(KEY_LEN))


def encrypt(path, key_path):
    key = read_exact_key(key_path)
    nonce = os.urandom(NONCE_LEN)
    with open(path, "rb") as input_file:
        plaintext = input_file.read()
    ciphertext = crypt(key, nonce, plaintext)
    with open(path + ".enc", "wb") as output:
        output.write(nonce + ciphertext)


def decrypt(path, key_path):
    key = read_exact_key(key_path)
    with open(path, "rb") as input_file:
        packed = input_file.read()
    if len(packed) < NONCE_LEN:
        raise ValueError("ficheiro cifrado incompleto")
    nonce = packed[:NONCE_LEN]
    ciphertext = packed[NONCE_LEN:]
    plaintext = crypt(key, nonce, ciphertext)
    with open(path + ".dec", "wb") as output:
        output.write(plaintext)


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "setup":
            setup(sys.argv[2])
        elif len(sys.argv) == 4 and sys.argv[1] == "enc":
            encrypt(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 4 and sys.argv[1] == "dec":
            decrypt(sys.argv[2], sys.argv[3])
        else:
            usage()
    except (OSError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
