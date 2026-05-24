#!/usr/bin/env python3
import os
import sys
import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 32
ITERATIONS = 200000


def usage():
    print("usage:")
    print("  python3 pbenc_aes_ctr_hmac.py enc <fich>")
    print("  python3 pbenc_aes_ctr_hmac.py dec <fich>")
    sys.exit(1)


def derive(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    keymat = kdf.derive(passphrase)
    return keymat[:32], keymat[32:]


def read_pass():
    return getpass.getpass("passphrase: ").encode()


def aes_ctr_crypt(key, nonce, data):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    ctx = cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def make_tag(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def enc(path):
    with open(path, "rb") as f:
        ptxt = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    enc_key, mac_key = derive(read_pass(), salt)
    ctxt = aes_ctr_crypt(enc_key, nonce, ptxt)

    header_ctxt = salt + nonce + ctxt
    tag = make_tag(mac_key, header_ctxt)

    with open(path + ".enc", "wb") as f:
        f.write(header_ctxt + tag)


def dec(path):
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("ficheiro cifrado inválido")

    salt = data[:SALT_SIZE]
    nonce = data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = data[-TAG_SIZE:]
    ctxt = data[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    enc_key, mac_key = derive(read_pass(), salt)
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(salt + nonce + ctxt)
    h.verify(tag)

    ptxt = aes_ctr_crypt(enc_key, nonce, ctxt)
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
