from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96 bits para AES-GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext  # juntar tudo para envio

def decrypt_message(key: bytes, data: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)
