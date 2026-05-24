from client_connection import send_request
from crypto_utils import (
    GROUP_KEY_SHARE_TYPE,
    GROUP_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_TYPE,
    SESSION_INIT_TYPE,
    SESSION_RESPONSE_TYPE,
    build_message_aad,
    canonical_message_bytes,
    decrypt_from_sender,
    verify_signature,
)
from handlers.conversation_handler import save_to_history
from handlers.group_message_handler import (
    handle_group_delete_message,
    handle_group_key_share_message,
    handle_group_leave_message,
    process_incoming_group_message,
    update_groups,
)
from handlers.message_common import GROUP_ACTION_DELETE, GROUP_ACTION_LEAVE, GROUP_CONTROL_TYPE, parse_json_object
from handlers.offline_message_handler import process_incoming_offline_prekey_message
from handlers.online_session_handler import (
    process_online_session_message,
    process_session_init_message,
    process_session_response_message,
)
from handlers.private_message_handler import get_sender_public_key


def process_incoming_message(msg, state):
    message_id = msg.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        return False

    if state.has_seen_message(message_id):
        return True

    if msg.get("type") == SESSION_INIT_TYPE:
        process_session_init_message(msg, state, message_id)
        return state.has_seen_message(message_id)

    if msg.get("type") == SESSION_RESPONSE_TYPE:
        process_session_response_message(msg, state, message_id)
        return state.has_seen_message(message_id)

    if msg.get("type") == ONLINE_SESSION_MESSAGE_TYPE:
        process_online_session_message(msg, state, message_id)
        return state.has_seen_message(message_id)

    if msg.get("type") == OFFLINE_PREKEY_MESSAGE_TYPE:
        process_incoming_offline_prekey_message(msg, state, message_id)
        return state.has_seen_message(message_id)

    if msg.get("type") == GROUP_MESSAGE_TYPE:
        process_incoming_group_message(msg, state, message_id)
        return state.has_seen_message(message_id)

    for required_field in ["timestamp", "from", "to", "payload", "signature"]:
        if required_field not in msg:
            return False

    sender_key = get_sender_public_key(msg, state)
    sender = msg.get("from")

    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar assinatura de {sender}.")
        return False

    signed_part = {
        "message_id": message_id,
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
    }
    for optional_field in ["group_id"]:
        if optional_field in msg:
            signed_part[optional_field] = msg[optional_field]

    valid = verify_signature(canonical_message_bytes(signed_part), msg["signature"], sender_key)
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem {msg.get('message_id')}.")
        return False

    try:
        aad = build_message_aad(message_id, msg["from"], msg["to"], msg["timestamp"])
        plaintext = decrypt_from_sender(msg["payload"], state.private_key, state.x25519_private_key, aad)
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar a mensagem {msg.get('message_id')}: {exc}")
        return False

    control_payload = parse_json_object(plaintext)
    if control_payload is not None and control_payload.get("type") == GROUP_KEY_SHARE_TYPE:
        handle_group_key_share_message(state, msg, control_payload, message_id)
        return state.has_seen_message(message_id)

    if control_payload is not None and control_payload.get("type") == GROUP_CONTROL_TYPE:
        if not state.mark_message_seen(message_id):
            return False
        if msg.get("group_id") and control_payload.get("group_id") != msg.get("group_id"):
            print(f"[AVISO] metadados de grupo inconsistentes na mensagem {message_id}.")
            return state.has_seen_message(message_id)
        action = control_payload.get("action")
        if action == GROUP_ACTION_DELETE:
            handle_group_delete_message(state, msg, control_payload)
        elif action == GROUP_ACTION_LEAVE:
            handle_group_leave_message(state, msg, control_payload)
        else:
            print(f"[AVISO] ação de grupo inválida na mensagem {message_id}.")
        return state.has_seen_message(message_id)

    if msg.get("group_id"):
        print(f"[AVISO] mensagem de grupo privada sem payload de controlo ignorada: {message_id}.")
        return False

    if not save_to_history(state, msg, plaintext):
        return False

    print(f"\n[Nova mensagem] {sender}: {plaintext} ({msg['timestamp']})")
    return True

def sync_pending_messages(state, show_summary=True, announce=False):
    if announce:
        print("A sincronizar mensagens pendentes...")

    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "fetch_messages", "username": state.username},
    )

    if resp is None:
        if show_summary:
            print("Ligação perdida.")
        return None

    if resp.get("status") != "ok":
        if show_summary:
            print(resp.get("message", "erro ao sincronizar mensagens"))
        return None

    messages = resp.get("messages", [])
    if not messages:
        if state.groups_dirty:
            update_groups(state)
        if show_summary:
            print("Sem mensagens pendentes.")
        return 0

    processed_message_ids = []
    for msg in messages:
        if process_incoming_message(msg, state):
            message_id = msg.get("message_id")
            if isinstance(message_id, str) and message_id and message_id not in processed_message_ids:
                processed_message_ids.append(message_id)

    if state.groups_dirty:
        if not update_groups(state):
            processed_message_ids = []

    if processed_message_ids:
        ack_resp = send_request(
            state.sock,
            state.response_queue,
            state.stop_event,
            {
                "command": "ack_messages",
                "username": state.username,
                "message_ids": processed_message_ids,
            },
        )
        if ack_resp is None:
            print("Ligação perdida ao confirmar mensagens processadas.")
        elif ack_resp.get("status") != "ok":
            print(ack_resp.get("message", "erro ao confirmar mensagens processadas"))

    if show_summary:
        print(f"Sincronização concluída: {len(processed_message_ids)} mensagem(ns).")
    return len(processed_message_ids)

def cmd_sync(state):
    return sync_pending_messages(state)
