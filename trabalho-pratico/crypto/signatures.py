import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from crypto.constants import (
    GROUP_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_TYPE,
    SESSION_INIT_TYPE,
    SESSION_RESPONSE_TYPE,
)
from crypto.serialization import x25519_public_key_from_pem

def build_session_handshake_signing_data(msg: dict) -> bytes:
    return canonical_message_bytes({
        "type": msg["type"],
        "session_id": msg["session_id"],
        "from": msg["from"],
        "to": msg["to"],
        "ephemeral_public_key": msg["ephemeral_public_key"],
        "timestamp": msg["timestamp"],
    })

def verify_session_ephemeral_signature(msg: dict, identity_public_key) -> bool:
    required = ["type", "session_id", "from", "to", "ephemeral_public_key", "timestamp", "signature"]
    if not isinstance(msg, dict) or not all(isinstance(msg.get(field), str) and msg.get(field) for field in required):
        return False
    if msg.get("type") not in {SESSION_INIT_TYPE, SESSION_RESPONSE_TYPE}:
        return False
    try:
        x25519_public_key_from_pem(msg["ephemeral_public_key"])
        signing_data = build_session_handshake_signing_data(msg)
    except Exception:
        return False
    return verify_signature(signing_data, msg["signature"], identity_public_key)

def group_message_signed_part(msg: dict):
    signed_part = {
        "type": GROUP_MESSAGE_TYPE,
        "group_id": msg["group_id"],
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
    }
    return signed_part

def offline_prekey_message_signed_part(msg: dict):
    return {
        "type": OFFLINE_PREKEY_MESSAGE_TYPE,
        "version": msg["version"],
        "algorithm": msg["algorithm"],
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "prekey_id": msg["prekey_id"],
        "ephemeral_public_key": msg["ephemeral_public_key"],
        "payload": msg["payload"],
    }

def online_session_message_signed_part(msg: dict):
    return {
        "type": ONLINE_SESSION_MESSAGE_TYPE,
        "version": msg["version"],
        "algorithm": msg["algorithm"],
        "session_id": msg["session_id"],
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "counter": msg["counter"],
        "payload": msg["payload"],
    }

def sign_message(data: bytes, private_key) -> str:
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def canonical_message_bytes(message_dict: dict) -> bytes:
    return json.dumps(message_dict, sort_keys=True, separators=(",", ":")).encode()

def e2ee_public_key_binding_bytes(username: str, e2ee_public_key_pem: str) -> bytes:
    return canonical_message_bytes({
        "type": "e2ee_public_key",
        "version": 1,
        "username": username,
        "e2ee_public_key": e2ee_public_key_pem,
    })
