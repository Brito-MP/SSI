import os
import sys
import hmac
import getpass
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


ENC_KEY_SIZE = 32
MAC_KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 32
ITERATIONS = 390000


def usage():
    print("Uso:")
    print("  python3 pbenc_aes_ctr_hmac.py enc <fich>")
    print("  python3 pbenc_aes_ctr_hmac.py dec <fich>")
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def derive_keys(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=ENC_KEY_SIZE + MAC_KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )

    key_material = kdf.derive(password)

    enc_key = key_material[:ENC_KEY_SIZE]
    mac_key = key_material[ENC_KEY_SIZE:]

    return enc_key, mac_key


def aes_ctr_crypt(data, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    ctx = cipher.encryptor()

    return ctx.update(data) + ctx.finalize()


def enc(fich):
    plaintext = read_file(fich)

    password = getpass.getpass("Passphrase: ").encode()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    enc_key, mac_key = derive_keys(password, salt)

    ciphertext = aes_ctr_crypt(plaintext, enc_key, nonce)

    header_and_ciphertext = salt + nonce + ciphertext
    tag = hmac.new(mac_key, header_and_ciphertext, hashlib.sha256).digest()

    write_file(fich + ".enc", header_and_ciphertext + tag)


def dec(fich):
    content = read_file(fich)

    if len(content) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise ValueError("Ficheiro inválido.")

    salt = content[:SALT_SIZE]
    nonce = content[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    tag = content[-TAG_SIZE:]
    ciphertext = content[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]

    password = getpass.getpass("Passphrase: ").encode()

    enc_key, mac_key = derive_keys(password, salt)

    header_and_ciphertext = salt + nonce + ciphertext
    expected_tag = hmac.new(mac_key, header_and_ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("MAC inválido. O ficheiro foi alterado ou a passphrase está errada.")

    plaintext = aes_ctr_crypt(ciphertext, enc_key, nonce)

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