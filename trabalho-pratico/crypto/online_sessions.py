import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_online_session_message(session_key: bytes, plaintext: str, aad: bytes | None = None):
    if not isinstance(session_key, bytes) or len(session_key) != 32:
        raise ValueError("session_key inválida")
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), aad)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def decrypt_online_session_message(session_key: bytes, payload: dict, aad: bytes | None = None):
    if not isinstance(session_key, bytes) or len(session_key) != 32:
        raise ValueError("session_key inválida")
    nonce = base64.b64decode(payload["nonce"].encode(), validate=True)
    ciphertext = base64.b64decode(payload["ciphertext"].encode(), validate=True)
    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, aad)
    return plaintext.decode()
