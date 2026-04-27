import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


KEY_SIZE = 32
IV_SIZE = 16
BLOCK_SIZE = 128


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def usage():
    print("Uso:")
    print("  python3 cfich_aes_cbc.py setup <fkey>")
    print("  python3 cfich_aes_cbc.py enc <fich> <fkey>")
    print("  python3 cfich_aes_cbc.py dec <fich> <fkey>")
    sys.exit(1)


def load_key(fkey):
    key = read_file(fkey)

    if len(key) != KEY_SIZE:
        raise ValueError("A chave AES deve ter 32 bytes.")

    return key


def setup(fkey):
    key = os.urandom(KEY_SIZE)
    write_file(fkey, key)


def enc(fich, fkey):
    key = load_key(fkey)
    plaintext = read_file(fich)

    iv = os.urandom(IV_SIZE)

    padder = padding.PKCS7(BLOCK_SIZE).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    write_file(fich + ".enc", iv + ciphertext)


def dec(fich, fkey):
    key = load_key(fkey)
    content = read_file(fich)

    iv = content[:IV_SIZE]
    ciphertext = content[IV_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    write_file(fich + ".dec", plaintext)


def main():
    if len(sys.argv) < 3:
        usage()

    op = sys.argv[1]

    if op == "setup" and len(sys.argv) == 3:
        setup(sys.argv[2])
    elif op == "enc" and len(sys.argv) == 4:
        enc(sys.argv[2], sys.argv[3])
    elif op == "dec" and len(sys.argv) == 4:
        dec(sys.argv[2], sys.argv[3])
    else:
        usage()


if __name__ == "__main__":
    main()