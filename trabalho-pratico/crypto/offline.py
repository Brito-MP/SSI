import base64
import os

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.aad import build_offline_prekey_aad
from crypto.key_derivation import _derive_offline_prekey_message_key
from crypto.serialization import (
    _x25519_public_raw,
    generate_x25519_keypair,
    public_key_to_pem,
    x25519_private_key_from_pem,
    x25519_public_key_from_pem,
)

def encrypt_for_signed_prekey(
    plaintext: str,
    recipient_prekey: dict,
    sender: str,
    recipient: str,
    message_id: str,
    timestamp: str,
):
    prekey_id = recipient_prekey["prekey_id"]
    recipient_prekey_public_key = x25519_public_key_from_pem(recipient_prekey["public_key"])
    sender_ephemeral_private_key, sender_ephemeral_public_key = generate_x25519_keypair()
    sender_ephemeral_raw = _x25519_public_raw(sender_ephemeral_public_key)
    recipient_prekey_raw = _x25519_public_raw(recipient_prekey_public_key)

    shared_secret = sender_ephemeral_private_key.exchange(recipient_prekey_public_key)
    aes_key = _derive_offline_prekey_message_key(
        shared_secret,
        sender_ephemeral_raw,
        recipient_prekey_raw,
        prekey_id,
    )

    ephemeral_public_key_pem = public_key_to_pem(sender_ephemeral_public_key)
    aad = build_offline_prekey_aad(
        message_id,
        sender,
        recipient,
        timestamp,
        prekey_id,
        ephemeral_public_key_pem,
    )
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), aad)

    return {
        "prekey_id": prekey_id,
        "ephemeral_public_key": ephemeral_public_key_pem,
        "payload": {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        },
    }

def decrypt_from_signed_prekey(
    payload: dict,
    recipient_prekey_private_key,
    ephemeral_public_key_pem: str,
    prekey_id: str,
    sender: str,
    recipient: str,
    message_id: str,
    timestamp: str,
) -> str:
    if isinstance(recipient_prekey_private_key, str):
        recipient_prekey_private_key = x25519_private_key_from_pem(recipient_prekey_private_key)
    if not isinstance(recipient_prekey_private_key, x25519.X25519PrivateKey):
        raise TypeError("chave privada de prekey não é X25519")

    sender_ephemeral_public_key = x25519_public_key_from_pem(ephemeral_public_key_pem)
    sender_ephemeral_raw = _x25519_public_raw(sender_ephemeral_public_key)
    recipient_prekey_raw = _x25519_public_raw(recipient_prekey_private_key.public_key())
    shared_secret = recipient_prekey_private_key.exchange(sender_ephemeral_public_key)
    aes_key = _derive_offline_prekey_message_key(
        shared_secret,
        sender_ephemeral_raw,
        recipient_prekey_raw,
        prekey_id,
    )

    aad = build_offline_prekey_aad(
        message_id,
        sender,
        recipient,
        timestamp,
        prekey_id,
        ephemeral_public_key_pem,
    )
    nonce = base64.b64decode(payload["nonce"].encode(), validate=True)
    ciphertext = base64.b64decode(payload["ciphertext"].encode(), validate=True)
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    return plaintext.decode()
