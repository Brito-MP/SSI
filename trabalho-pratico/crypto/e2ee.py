import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.constants import E2EE_MESSAGE_VERSION
from crypto.key_derivation import _derive_e2ee_v2_key
from crypto.serialization import _x25519_public_raw, generate_x25519_keypair

def encrypt_for_recipient(plaintext: str, recipient_public_key, aad: bytes | None = None):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)

    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }

def encrypt_for_recipient_v2(plaintext: str, recipient_x25519_public_key, aad: bytes | None = None):
    if not isinstance(recipient_x25519_public_key, x25519.X25519PublicKey):
        raise TypeError("chave pública do destinatário não é X25519")

    sender_ephemeral_private_key, sender_ephemeral_public_key = generate_x25519_keypair()
    sender_ephemeral_raw = _x25519_public_raw(sender_ephemeral_public_key)
    recipient_static_raw = _x25519_public_raw(recipient_x25519_public_key)

    shared_secret = sender_ephemeral_private_key.exchange(recipient_x25519_public_key)
    aes_key = _derive_e2ee_v2_key(shared_secret, sender_ephemeral_raw, recipient_static_raw)

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)

    return {
        "version": E2EE_MESSAGE_VERSION,
        "sender_ephemeral_key": base64.b64encode(sender_ephemeral_raw).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def decrypt_from_sender_v1(payload: dict, recipient_private_key, aad: bytes | None = None) -> str:
    encrypted_key = base64.b64decode(payload["encrypted_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    aes_key = recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode()

def decrypt_from_sender_v2(payload: dict, recipient_x25519_private_key, aad: bytes | None = None) -> str:
    if not isinstance(recipient_x25519_private_key, x25519.X25519PrivateKey):
        raise TypeError("chave privada E2EE não é X25519")

    sender_ephemeral_raw = base64.b64decode(payload["sender_ephemeral_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    sender_ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(sender_ephemeral_raw)
    recipient_static_raw = _x25519_public_raw(recipient_x25519_private_key.public_key())
    shared_secret = recipient_x25519_private_key.exchange(sender_ephemeral_public_key)
    aes_key = _derive_e2ee_v2_key(shared_secret, sender_ephemeral_raw, recipient_static_raw)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode()

def decrypt_from_sender(payload: dict, recipient_private_key, recipient_x25519_private_key=None, aad: bytes | None = None) -> str:
    if payload.get("version") == E2EE_MESSAGE_VERSION:
        return decrypt_from_sender_v2(payload, recipient_x25519_private_key, aad)
    return decrypt_from_sender_v1(payload, recipient_private_key, aad)
