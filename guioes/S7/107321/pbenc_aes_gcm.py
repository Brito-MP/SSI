#!/usr/bin/env python3
import os
import sys
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 12
ITERATIONS = 200000


def usage():
    print("usage:")
    print("  python3 pbenc_aes_gcm.py enc <fich>")
    print("  python3 pbenc_aes_gcm.py dec <fich>")
    sys.exit(1)


def derive(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(passphrase)


def read_pass():
    return getpass.getpass("passphrase: ").encode()


def enc(path):
    with open(path, "rb") as f:
        ptxt = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive(read_pass(), salt)
    ctxt = AESGCM(key).encrypt(nonce, ptxt, None)

    with open(path + ".enc", "wb") as f:
        f.write(salt + nonce + ctxt)


def dec(path):
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < SALT_SIZE + NONCE_SIZE + 16:
        raise ValueError("ficheiro cifrado inválido")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ctxt = data[SALT_SIZE + NONCE_SIZE:]

    key = derive(read_pass(), salt)
    ptxt = AESGCM(key).decrypt(nonce, ctxt, None)

    with open(path + ".dec", "wb") as f:
        f.write(ptxt)


def main():
    if len(sys.argv) != 3:
        usage()
    if sys.argv[1] == "enc":
        enc(sys.argv[2])
    elif sys.argv[1] == "dec":
        dec(sys.argv[2])
    else:
        usage()


if __name__ == "__main__":
    main()
