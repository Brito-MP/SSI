from crypto_utils import (
    GROUP_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_TYPE,
    SESSION_INIT_TYPE,
    SESSION_RESPONSE_TYPE,
)
from protocol import send_json
from server.server_common import ONLINE_ONLY_MESSAGE_TYPES
from server.server_state import online_users, online_users_lock, remove_online_user_if_socket
from server.user_store import sender_certificate, sender_public_key
from server.validators import OPTIONAL_ENVELOPE_FIELDS
from storage import load_messages, messages_lock, save_messages


def build_envelope(msg: dict):
    if msg.get("type") in {SESSION_INIT_TYPE, SESSION_RESPONSE_TYPE}:
        return {
            "type": msg["type"],
            "session_id": msg["session_id"],
            "message_id": msg.get("message_id", msg["session_id"]),
            "timestamp": msg["timestamp"],
            "from": msg["from"],
            "to": msg["to"],
            "ephemeral_public_key": msg["ephemeral_public_key"],
            "signature": msg["signature"],
        }

    if msg.get("type") == ONLINE_SESSION_MESSAGE_TYPE:
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
            "payload": {
                "nonce": msg["payload"]["nonce"],
                "ciphertext": msg["payload"]["ciphertext"],
            },
            "signature": msg["signature"],
        }

    if msg.get("type") == OFFLINE_PREKEY_MESSAGE_TYPE:
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
            "payload": {
                "nonce": msg["payload"]["nonce"],
                "ciphertext": msg["payload"]["ciphertext"],
            },
            "signature": msg["signature"],
        }

    if msg.get("type") == GROUP_MESSAGE_TYPE:
        envelope = {
            "type": GROUP_MESSAGE_TYPE,
            "group_id": msg["group_id"],
            "message_id": msg["message_id"],
            "timestamp": msg["timestamp"],
            "from": msg["from"],
            "to": msg["to"],
            "payload": {
                "nonce": msg["payload"]["nonce"],
                "ciphertext": msg["payload"]["ciphertext"],
            },
            "signature": msg["signature"],
        }
        return envelope

    envelope = {
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
        "signature": msg["signature"],
    }
    for field in OPTIONAL_ENVELOPE_FIELDS:
        if field in msg:
            envelope[field] = msg[field]
    return envelope

def store_encrypted_message(msg: dict, envelope: dict | None = None):
    with messages_lock():
        messages = load_messages()
        if envelope is None:
            envelope = build_envelope(msg)
        messages.append(envelope)
        save_messages(messages)
    return envelope

def deliver_or_store_message(msg: dict, users: dict):
    envelope = build_envelope(msg)
    target = msg["to"]

    with online_users_lock:
        target_socket = online_users.get(target)

    if target_socket is not None:
        try:
            send_json(target_socket, {
                "command": "deliver_message",
                "sender_public_key": sender_public_key(users, msg["from"]),
                "sender_certificate": sender_certificate(users, msg["from"]),
                **envelope,
            })
        except OSError:
            remove_online_user_if_socket(target, target_socket)
        else:
            return envelope, True, False

    if msg.get("type") in ONLINE_ONLY_MESSAGE_TYPES:
        return envelope, False, False

    store_encrypted_message(msg, envelope)
    return envelope, False, True

def get_pending_messages(username: str):
    with messages_lock():
        messages = load_messages()
        pending = [m for m in messages if m.get("to") == username]
    return pending

def ack_pending_messages(username: str, message_ids):
    ack_ids = {message_id for message_id in message_ids if isinstance(message_id, str)}
    with messages_lock():
        messages = load_messages()
        remaining = []
        removed = 0
        for msg in messages:
            if msg.get("to") == username and msg.get("message_id") in ack_ids:
                removed += 1
                continue
            remaining.append(msg)
        save_messages(remaining)
    return removed

def enrich_with_sender_keys(messages, users: dict):
    enriched = []
    for msg in messages:
        enriched.append({
            **msg,
            "sender_public_key": sender_public_key(users, msg["from"]),
            "sender_certificate": sender_certificate(users, msg["from"]),
        })
    return enriched
