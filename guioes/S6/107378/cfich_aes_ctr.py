#!/usr/bin/env python3
import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY_LEN = 32
NONCE_LEN = 16


def usage():
    print("uso: python3 cfich_aes_ctr.py setup <fkey>")
    print("uso: python3 cfich_aes_ctr.py enc <fich> <fkey>")
    print("uso: python3 cfich_aes_ctr.py dec <fich> <fkey>")
    sys.exit(1)


def read_key(path):
    with open(path, "rb") as key_file:
        key = key_file.read()
    if len(key) != KEY_LEN:
        raise ValueError("a chave AES deve ter 32 bytes")
    return key


def apply_ctr(key, nonce, data):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    stream = cipher.encryptor()
    return stream.update(data) + stream.finalize()


def setup(path):
    with open(path, "wb") as output:
        output.write(os.urandom(KEY_LEN))


def encrypt(path, key_path):
    key = read_key(key_path)
    nonce = os.urandom(NONCE_LEN)
    with open(path, "rb") as input_file:
        plaintext = input_file.read()
    with open(path + ".enc", "wb") as output:
        output.write(nonce + apply_ctr(key, nonce, plaintext))


def decrypt(path, key_path):
    key = read_key(key_path)
    with open(path, "rb") as input_file:
        packed = input_file.read()
    if len(packed) < NONCE_LEN:
        raise ValueError("ficheiro AES-CTR invalido")
    nonce = packed[:NONCE_LEN]
    ciphertext = packed[NONCE_LEN:]
    with open(path + ".dec", "wb") as output:
        output.write(apply_ctr(key, nonce, ciphertext))


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
