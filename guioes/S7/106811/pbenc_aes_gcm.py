import os
import sys
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
ITERATIONS = 390000


def usage():
    print("Uso:")
    print("  python3 pbenc_aes_gcm.py enc <fich>")
    print("  python3 pbenc_aes_gcm.py dec <fich>")
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )

    return kdf.derive(password)


def enc(fich):
    plaintext = read_file(fich)

    password = getpass.getpass("Passphrase: ").encode()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    write_file(fich + ".enc", salt + nonce + ciphertext)


def dec(fich):
    content = read_file(fich)

    if len(content) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Ficheiro inválido.")

    salt = content[:SALT_SIZE]
    nonce = content[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = content[SALT_SIZE + NONCE_SIZE:]

    password = getpass.getpass("Passphrase: ").encode()

    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    write_file(fich + ".dec", plaintext)


def main():
    if len(sys.argv) != 3:
        usage()

    op = sys.argv[1]

    if op == "enc":
        enc(sys.argv[2])
    elif op == "dec":
        dec(sys.argv[2])
    else:
        usage()


if __name__ == "__main__":
    main()