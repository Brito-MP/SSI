import json

from crypto.constants import (
    OFFLINE_PREKEY_MESSAGE_ALGORITHM,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_VERSION,
    ONLINE_SESSION_MESSAGE_ALGORITHM,
    ONLINE_SESSION_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_VERSION,
)

def build_message_aad(message_id, sender, recipient, timestamp) -> bytes:
    aad_obj = {
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def build_offline_prekey_aad(message_id, sender, recipient, timestamp, prekey_id, ephemeral_public_key) -> bytes:
    aad_obj = {
        "type": OFFLINE_PREKEY_MESSAGE_TYPE,
        "version": OFFLINE_PREKEY_MESSAGE_VERSION,
        "algorithm": OFFLINE_PREKEY_MESSAGE_ALGORITHM,
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
        "prekey_id": prekey_id,
        "ephemeral_public_key": ephemeral_public_key,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def build_online_session_aad(session_id, message_id, sender, recipient, timestamp, counter) -> bytes:
    aad_obj = {
        "type": ONLINE_SESSION_MESSAGE_TYPE,
        "version": ONLINE_SESSION_MESSAGE_VERSION,
        "algorithm": ONLINE_SESSION_MESSAGE_ALGORITHM,
        "session_id": session_id,
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
        "counter": counter,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def build_group_aad(group_id, sender, recipient, message_id, timestamp) -> bytes:
    aad_obj = {
        "group_id": group_id,
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
