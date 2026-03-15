import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from crypto_utils import (
    canonical_message_bytes,
    decrypt_from_sender,
    encrypt_for_recipient,
    generate_message_id,
    public_key_from_pem,
    sign_message,
    utc_timestamp,
    verify_signature,
)
from client_connection import send_request
from handlers.conversation_handler import save_to_history


def build_message_envelope(my_username, target, text, my_private_key, target_public_key):
    payload = encrypt_for_recipient(text, target_public_key)

    envelope_to_sign = {
        "message_id": generate_message_id(),
        "timestamp": utc_timestamp(),
        "from": my_username,
        "to": target,
        "payload": payload,
    }

    signature = sign_message(canonical_message_bytes(envelope_to_sign), my_private_key)

    return {
        **envelope_to_sign,
        "signature": signature,
    }


def get_sender_public_key(msg, state):
    sender = msg["from"]

    if msg.get("sender_public_key"):
        try:
            parsed_key = public_key_from_pem(msg["sender_public_key"])
            with state.key_cache_lock:
                state.key_cache[sender] = parsed_key
        except Exception:
            pass

    with state.key_cache_lock:
        return state.key_cache.get(sender)


def process_incoming_message(msg, state):
    sender_key = get_sender_public_key(msg, state)
    sender = msg.get("from")

    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar assinatura de {sender}.")
        return

    signed_part = {
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
    }

    valid = verify_signature(canonical_message_bytes(signed_part), msg["signature"], sender_key)
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem {msg.get('message_id')}.")
        return

    try:
        plaintext = decrypt_from_sender(msg["payload"], state.private_key)
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar a mensagem {msg.get('message_id')}: {exc}")
        return

    save_to_history(state, msg, plaintext)
    print(f"\n[Nova mensagem] {sender}: {plaintext} ({msg['timestamp']})")


def get_user_key(state, target):
    with state.key_cache_lock:
        if target in state.key_cache:
            return state.key_cache[target]

    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "get_user_key", "target": target},
    )

    if resp is None:
        print("Ligação perdida ao pedir chave pública.")
        return None

    if resp.get("status") != "ok":
        print(resp.get("message", "erro a obter chave pública"))
        return None

    try:
        key = public_key_from_pem(resp["public_key"])
    except Exception as exc:
        print(f"Erro ao carregar chave pública de {target}: {exc}")
        return None

    with state.key_cache_lock:
        state.key_cache[target] = key
    return key


def cmd_send(state, target, text):
    target_public_key = get_user_key(state, target)
    if target_public_key is None:
        return

    envelope = build_message_envelope(state.username, target, text, state.private_key, target_public_key)

    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "send_message", **envelope},
    )

    if resp is None:
        print("Ligação perdida ao enviar mensagem.")
        return

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao enviar mensagem"))
        return

    save_to_history(state, envelope, text)
    print(f"Mensagem enviada com sucesso. message_id={resp.get('message_id')}")


def cmd_sync(state):
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "fetch_messages", "username": state.username},
    )

    if resp is None:
        print("Ligação perdida.")
        return

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao sincronizar mensagens"))
        return

    messages = resp.get("messages", [])
    if not messages:
        print("Sem mensagens pendentes.")
        return

    for msg in messages:
        process_incoming_message(msg, state)

    print(f"Sincronização concluída: {len(messages)} mensagem(ns).")
