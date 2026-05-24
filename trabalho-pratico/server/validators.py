from crypto_utils import (
    E2EE_MESSAGE_VERSION,
    GROUP_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_ALGORITHM,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_VERSION,
    ONLINE_SESSION_MESSAGE_ALGORITHM,
    ONLINE_SESSION_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_VERSION,
    SESSION_INIT_TYPE,
    SESSION_RESPONSE_TYPE,
    x25519_public_key_from_pem,
)

REQUIRED_V1_PAYLOAD_FIELDS = {"nonce", "ciphertext", "encrypted_key"}
REQUIRED_V2_PAYLOAD_FIELDS = {"version", "nonce", "ciphertext", "sender_ephemeral_key"}
REQUIRED_ENVELOPE_FIELDS = {
    "message_id",
    "timestamp",
    "from",
    "to",
    "payload",
    "signature",
}
OPTIONAL_ENVELOPE_FIELDS = {"group_id"}
FORBIDDEN_PLAINTEXT_GROUP_FIELDS = {"group_name", "group_members", "group_action", "members", "action", "text"}
REQUIRED_GROUP_MESSAGE_FIELDS = {
    "type",
    "group_id",
    "message_id",
    "timestamp",
    "from",
    "to",
    "payload",
    "signature",
}
REQUIRED_OFFLINE_PREKEY_MESSAGE_FIELDS = {
    "type",
    "version",
    "algorithm",
    "message_id",
    "timestamp",
    "from",
    "to",
    "prekey_id",
    "ephemeral_public_key",
    "payload",
    "signature",
}
REQUIRED_SESSION_HANDSHAKE_FIELDS = {
    "type",
    "session_id",
    "timestamp",
    "from",
    "to",
    "ephemeral_public_key",
    "signature",
}
REQUIRED_ONLINE_SESSION_MESSAGE_FIELDS = {
    "type",
    "version",
    "algorithm",
    "session_id",
    "message_id",
    "timestamp",
    "from",
    "to",
    "counter",
    "payload",
    "signature",
}


def is_valid_payload(payload: dict) -> bool:
    if not isinstance(payload, dict):
        return False

    if payload.get("version") == E2EE_MESSAGE_VERSION:
        return REQUIRED_V2_PAYLOAD_FIELDS.issubset(payload.keys()) and all(
            isinstance(payload[field], str)
            for field in ["nonce", "ciphertext", "sender_ephemeral_key"]
        )

    return REQUIRED_V1_PAYLOAD_FIELDS.issubset(payload.keys()) and all(
        isinstance(payload[field], str)
        for field in ["nonce", "ciphertext", "encrypted_key"]
    )

def is_valid_group_payload(payload: dict) -> bool:
    if not isinstance(payload, dict):
        return False
    return all(isinstance(payload.get(field), str) and payload.get(field) for field in ["nonce", "ciphertext"])

def is_valid_offline_prekey_payload(payload: dict) -> bool:
    if not isinstance(payload, dict):
        return False
    return all(isinstance(payload.get(field), str) and payload.get(field) for field in ["nonce", "ciphertext"])

def is_valid_session_handshake(msg: dict) -> bool:
    if not REQUIRED_SESSION_HANDSHAKE_FIELDS.issubset(msg.keys()):
        return False
    if msg.get("type") not in {SESSION_INIT_TYPE, SESSION_RESPONSE_TYPE}:
        return False
    if not all(
        isinstance(msg[field], str) and msg[field]
        for field in ["type", "session_id", "timestamp", "from", "to", "ephemeral_public_key", "signature"]
    ):
        return False
    try:
        x25519_public_key_from_pem(msg["ephemeral_public_key"])
    except Exception:
        return False
    return True

def is_valid_online_session_message(msg: dict) -> bool:
    if not REQUIRED_ONLINE_SESSION_MESSAGE_FIELDS.issubset(msg.keys()):
        return False
    if msg.get("version") != ONLINE_SESSION_MESSAGE_VERSION:
        return False
    if msg.get("algorithm") != ONLINE_SESSION_MESSAGE_ALGORITHM:
        return False
    if not isinstance(msg.get("counter"), int) or msg["counter"] < 1:
        return False
    if not all(
        isinstance(msg[field], str) and msg[field]
        for field in ["type", "algorithm", "session_id", "message_id", "timestamp", "from", "to", "signature"]
    ):
        return False
    return is_valid_group_payload(msg.get("payload"))

def is_valid_envelope(msg: dict) -> bool:
    if any(field in msg for field in FORBIDDEN_PLAINTEXT_GROUP_FIELDS):
        return False

    if msg.get("type") in {SESSION_INIT_TYPE, SESSION_RESPONSE_TYPE}:
        return is_valid_session_handshake(msg)

    if msg.get("type") == ONLINE_SESSION_MESSAGE_TYPE:
        return is_valid_online_session_message(msg)

    if msg.get("type") == OFFLINE_PREKEY_MESSAGE_TYPE:
        if not REQUIRED_OFFLINE_PREKEY_MESSAGE_FIELDS.issubset(msg.keys()):
            return False
        if msg.get("version") != OFFLINE_PREKEY_MESSAGE_VERSION:
            return False
        if msg.get("algorithm") != OFFLINE_PREKEY_MESSAGE_ALGORITHM:
            return False
        if not all(
            isinstance(msg[field], str) and msg[field]
            for field in ["type", "algorithm", "message_id", "timestamp", "from", "to", "prekey_id", "ephemeral_public_key", "signature"]
        ):
            return False
        try:
            x25519_public_key_from_pem(msg["ephemeral_public_key"])
        except Exception:
            return False
        return is_valid_offline_prekey_payload(msg.get("payload"))

    if msg.get("type") == GROUP_MESSAGE_TYPE:
        if not REQUIRED_GROUP_MESSAGE_FIELDS.issubset(msg.keys()):
            return False
        if not all(
            isinstance(msg[field], str) and msg[field]
            for field in ["type", "group_id", "message_id", "timestamp", "from", "to", "signature"]
        ):
            return False
        return is_valid_group_payload(msg.get("payload"))

    if not REQUIRED_ENVELOPE_FIELDS.issubset(msg.keys()):
        return False

    if not is_valid_payload(msg.get("payload")):
        return False

    if not all(isinstance(msg[field], str) for field in ["message_id", "timestamp", "from", "to", "signature"]):
        return False

    return True
