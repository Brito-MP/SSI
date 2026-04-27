import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY_SIZE = 32
NONCE_SIZE = 16


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def usage():
    print("Uso:")
    print("  python3 cfich_aes_ctr.py setup <fkey>")
    print("  python3 cfich_aes_ctr.py enc <fich> <fkey>")
    print("  python3 cfich_aes_ctr.py dec <fich> <fkey>")
    sys.exit(1)


def load_key(fkey):
    key = read_file(fkey)

    if len(key) != KEY_SIZE:
        raise ValueError("A chave AES deve ter 32 bytes.")

    return key


def aes_ctr_crypt(data, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    ctx = cipher.encryptor()

    return ctx.update(data) + ctx.finalize()


def setup(fkey):
    key = os.urandom(KEY_SIZE)
    write_file(fkey, key)


def enc(fich, fkey):
    key = load_key(fkey)
    plaintext = read_file(fich)

    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aes_ctr_crypt(plaintext, key, nonce)

    write_file(fich + ".enc", nonce + ciphertext)


def dec(fich, fkey):
    key = load_key(fkey)
    content = read_file(fich)

    nonce = content[:NONCE_SIZE]
    ciphertext = content[NONCE_SIZE:]

    plaintext = aes_ctr_crypt(ciphertext, key, nonce)

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