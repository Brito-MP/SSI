import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_group_key() -> str:
    key = AESGCM.generate_key(bit_length=256)
    return base64.b64encode(key).decode()

def decode_group_key(group_key: str) -> bytes:
    if not isinstance(group_key, str) or not group_key:
        raise ValueError("group_key inválida")

    try:
        key = base64.b64decode(group_key.encode(), validate=True)
    except Exception as exc:
        raise ValueError("group_key inválida") from exc

    if len(key) != 32:
        raise ValueError("group_key deve ter 256 bits")
    return key

def is_valid_group_key(group_key: str) -> bool:
    try:
        decode_group_key(group_key)
    except Exception:
        return False
    return True

def encrypt_group_payload(group_key: str, payload: dict, aad: bytes | None = None):
    key = decode_group_key(group_key)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def decrypt_group_payload(group_key: str, nonce_b64: str, ciphertext_b64: str, aad: bytes | None = None):
    key = decode_group_key(group_key)
    nonce = base64.b64decode(nonce_b64.encode(), validate=True)
    ciphertext = base64.b64decode(ciphertext_b64.encode(), validate=True)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    payload = json.loads(plaintext.decode())
    if not isinstance(payload, dict):
        raise ValueError("payload de grupo inválido")
    return payload
