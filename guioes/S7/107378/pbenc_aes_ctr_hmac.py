#!/usr/bin/env python3
import getpass
import os
import sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32
ITERATIONS = 260000


def usage():
    print("uso: python3 pbenc_aes_ctr_hmac.py enc <fich>")
    print("uso: python3 pbenc_aes_ctr_hmac.py dec <fich>")
    sys.exit(1)


def passphrase():
    if sys.stdin.isatty():
        return getpass.getpass("passphrase: ").encode()
    return sys.stdin.readline().rstrip("\n").encode()


def derive(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=ITERATIONS,
    )
    material = kdf.derive(password)
    return material[:32], material[32:]


def ctr_crypt(key, nonce, data):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    ctx = cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def tag_for(key, data):
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def encrypt(path):
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = derive(passphrase(), salt)
    with open(path, "rb") as input_file:
        plaintext = input_file.read()

    body = salt + nonce + ctr_crypt(enc_key, nonce, plaintext)
    with open(path + ".enc", "wb") as output:
        output.write(body + tag_for(mac_key, body))


def decrypt(path):
    with open(path, "rb") as input_file:
        packed = input_file.read()
    if len(packed) < SALT_LEN + NONCE_LEN + TAG_LEN:
        raise ValueError("ficheiro cifrado invalido")

    body = packed[:-TAG_LEN]
    received_tag = packed[-TAG_LEN:]
    salt = body[:SALT_LEN]
    nonce = body[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = body[SALT_LEN + NONCE_LEN:]
    enc_key, mac_key = derive(passphrase(), salt)

    mac = hmac.HMAC(mac_key, hashes.SHA256())
    mac.update(body)
    mac.verify(received_tag)

    with open(path + ".dec", "wb") as output:
        output.write(ctr_crypt(enc_key, nonce, ciphertext))


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "enc":
            encrypt(sys.argv[2])
        elif len(sys.argv) == 3 and sys.argv[1] == "dec":
            decrypt(sys.argv[2])
        else:
            usage()
    except InvalidSignature:
        print("erro: HMAC invalido", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
