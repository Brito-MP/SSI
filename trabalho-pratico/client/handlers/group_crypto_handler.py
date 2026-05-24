import json
import re

from crypto_utils import (
    GROUP_KEY_SHARE_TYPE,
    GROUP_MESSAGE_TYPE,
    build_group_aad,
    canonical_message_bytes,
    decrypt_group_payload,
    group_message_signed_part,
    normalize_group_key_version,
    sign_message,
    verify_signature,
)
from handlers.conversation_handler import save_to_history
from handlers.message_common import (
    GROUP_ACTION_KEY_ROTATION,
    GROUP_ACTION_MESSAGE,
    GROUP_CONTROL_TYPE,
    GROUP_ROTATION_LEADER_FIELD,
    GROUP_ROTATION_PENDING_FIELD,
)
from handlers.private_message_handler import get_sender_public_key
from crypto_utils import is_valid_group_key


def group_id_from_name(name: str):
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    slug = slug.strip("-")
    if not slug:
        return None
    return f"group-{slug}"

def group_key_share_plaintext(group_id, group):
    payload = {
        "type": GROUP_KEY_SHARE_TYPE,
        "group_id": group_id,
        "group_name": group.get("name", group_id),
        "members": sorted(set(group.get("members", []))),
        "group_key": group["group_key"],
        "group_key_version": normalize_group_key_version(group.get("group_key_version")),
        "action": GROUP_ACTION_KEY_ROTATION,
    }
    return json.dumps(payload, separators=(",", ":"))

def group_control_plaintext(group_info, text, group_action):
    payload = {
        "type": GROUP_CONTROL_TYPE,
        "group_id": group_info["id"],
        "group_name": group_info.get("name", group_info["id"]),
        "members": sorted(set(group_info.get("members", []))),
        "text": text,
        "action": group_action,
    }
    return json.dumps(payload, separators=(",", ":"))

def build_group_message_payload(my_username, group_id, group, text, message_id, timestamp):
    return {
        "type": GROUP_MESSAGE_TYPE,
        "group_name": group.get("name", group_id),
        "members": sorted(set(group.get("members", []))),
        "text": text,
        "action": GROUP_ACTION_MESSAGE,
        "group_key_version": normalize_group_key_version(group.get("group_key_version")),
    }

def build_group_message_envelope(my_username, target, group_id, encrypted_payload, message_id, timestamp, my_private_key):
    envelope_to_sign = {
        "type": GROUP_MESSAGE_TYPE,
        "group_id": group_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from": my_username,
        "to": target,
        "payload": {
            "nonce": encrypted_payload["nonce"],
            "ciphertext": encrypted_payload["ciphertext"],
        },
    }
    signature = sign_message(canonical_message_bytes(group_message_signed_part(envelope_to_sign)), my_private_key)
    return {
        **envelope_to_sign,
        "signature": signature,
    }

def process_incoming_group_message(msg, state, message_id):
    required_fields = ["type", "group_id", "timestamp", "from", "to", "signature"]
    for required_field in required_fields:
        if not isinstance(msg.get(required_field), str) or not msg.get(required_field):
            return
    encrypted_payload = msg.get("payload")
    if not isinstance(encrypted_payload, dict):
        return
    if not all(isinstance(encrypted_payload.get(field), str) and encrypted_payload.get(field) for field in ["nonce", "ciphertext"]):
        return

    sender_key = get_sender_public_key(msg, state)
    sender = msg.get("from")
    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar assinatura de {sender}.")
        return

    group_id = msg["group_id"]
    group = state.groups.get(group_id)
    if not isinstance(group, dict) or not is_valid_group_key(group.get("group_key")):
        if isinstance(group, dict) and group.get(GROUP_ROTATION_PENDING_FIELD) is True:
            rotation_leader = group.get(GROUP_ROTATION_LEADER_FIELD, "outro membro")
            print(f"[AVISO] a aguardar nova group_key de {rotation_leader} para {group_id}.")
            return
        print(f"[AVISO] sem group_key local para decifrar mensagem do grupo {group_id}.")
        return

    valid = verify_signature(
        canonical_message_bytes(group_message_signed_part(msg)),
        msg["signature"],
        sender_key,
    )
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem de grupo {message_id}.")
        return

    group_key_version = normalize_group_key_version(group.get("group_key_version"))

    try:
        aad = build_group_aad(group_id, sender, msg["to"], message_id, msg["timestamp"])
        payload = decrypt_group_payload(group["group_key"], encrypted_payload["nonce"], encrypted_payload["ciphertext"], aad)
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar a mensagem de grupo {message_id}: {exc}")
        return

    if payload.get("type") != GROUP_MESSAGE_TYPE:
        return
    if payload.get("action") != GROUP_ACTION_MESSAGE:
        print(f"[AVISO] ação de grupo inválida na mensagem {message_id}.")
        return
    if normalize_group_key_version(payload.get("group_key_version")) != group_key_version:
        print(f"[AVISO] versão da group_key inconsistente na mensagem de grupo {message_id}.")
        return
    if not isinstance(payload.get("text"), str):
        return

    history_msg = {
        "message_id": message_id,
        "timestamp": msg["timestamp"],
        "from": sender,
        "to": group_id,
        "group_id": group_id,
        "group_name": payload.get("group_name", group.get("name", group_id)),
        "group_members": payload.get("members", group.get("members", [])),
    }

    if not save_to_history(state, history_msg, payload["text"]):
        return

    group_name = history_msg["group_name"]
    print(f"\n[Nova mensagem em {group_name}] {sender}: {payload['text']} ({msg['timestamp']})")
