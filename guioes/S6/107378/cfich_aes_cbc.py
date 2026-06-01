#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_LEN = 32
IV_LEN = 16
BLOCK_BITS = 128


def usage():
    print("uso: python3 cfich_aes_cbc.py setup <fkey>")
    print("uso: python3 cfich_aes_cbc.py enc <fich> <fkey>")
    print("uso: python3 cfich_aes_cbc.py dec <fich> <fkey>")
    sys.exit(1)


def read_key(path):
    with open(path, "rb") as key_file:
        key = key_file.read()
    if len(key) != KEY_LEN:
        raise ValueError("a chave AES deve ter 32 bytes")
    return key


def setup(path):
    with open(path, "wb") as output:
        output.write(os.urandom(KEY_LEN))


def encrypt(path, key_path):
    key = read_key(key_path)
    iv = os.urandom(IV_LEN)
    with open(path, "rb") as input_file:
        plaintext = input_file.read()

    padder = padding.PKCS7(BLOCK_BITS).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    with open(path + ".enc", "wb") as output:
        output.write(iv + ciphertext)


def decrypt(path, key_path):
    key = read_key(key_path)
    with open(path, "rb") as input_file:
        packed = input_file.read()
    if len(packed) < IV_LEN or (len(packed) - IV_LEN) % IV_LEN != 0:
        raise ValueError("ficheiro AES-CBC invalido")

    iv = packed[:IV_LEN]
    ciphertext = packed[IV_LEN:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    unpadder = padding.PKCS7(BLOCK_BITS).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
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
