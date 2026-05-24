import json

from crypto_utils import (
    ONLINE_SESSION_MESSAGE_ALGORITHM,
    ONLINE_SESSION_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_VERSION,
    build_online_session_aad,
    canonical_message_bytes,
    decrypt_online_session_message,
    encrypt_online_session_message,
    generate_message_id,
    online_session_message_signed_part,
    sign_message,
    utc_timestamp,
    verify_signature,
)
from handlers.conversation_handler import save_to_history
from handlers.message_common import GROUP_ACTION_MESSAGE, parse_json_object
from handlers.private_message_handler import get_sender_public_key


def build_online_session_message_envelope(state, target, text):
    with state.online_sessions_lock:
        session = state.online_sessions.get(target)
        if not isinstance(session, dict):
            return None
        session["send_counter"] = int(session.get("send_counter", 0)) + 1
        counter = session["send_counter"]
        session_key = session["session_key"]
        session_id = session["session_id"]

    message_id = generate_message_id()
    timestamp = utc_timestamp()
    plaintext = json.dumps({"text": text, "action": GROUP_ACTION_MESSAGE}, separators=(",", ":"))
    aad = build_online_session_aad(session_id, message_id, state.username, target, timestamp, counter)
    encrypted_payload = encrypt_online_session_message(session_key, plaintext, aad)
    envelope_to_sign = {
        "type": ONLINE_SESSION_MESSAGE_TYPE,
        "version": ONLINE_SESSION_MESSAGE_VERSION,
        "algorithm": ONLINE_SESSION_MESSAGE_ALGORITHM,
        "session_id": session_id,
        "message_id": message_id,
        "timestamp": timestamp,
        "from": state.username,
        "to": target,
        "counter": counter,
        "payload": encrypted_payload,
    }
    signature = sign_message(canonical_message_bytes(online_session_message_signed_part(envelope_to_sign)), state.private_key)
    return {
        **envelope_to_sign,
        "signature": signature,
    }

def process_online_session_message(msg, state, message_id):
    sender = msg.get("from")
    if msg.get("to") != state.username or not isinstance(sender, str):
        return
    required_fields = [
        "type",
        "version",
        "algorithm",
        "session_id",
        "timestamp",
        "from",
        "to",
        "counter",
        "payload",
        "signature",
    ]
    for required_field in required_fields:
        if required_field == "payload":
            if not isinstance(msg.get(required_field), dict):
                return
            continue
        if required_field in {"counter", "version"}:
            if not isinstance(msg.get(required_field), int):
                return
            continue
        if not isinstance(msg.get(required_field), str) or not msg.get(required_field):
            return
    if msg.get("version") != ONLINE_SESSION_MESSAGE_VERSION:
        return
    if msg.get("algorithm") != ONLINE_SESSION_MESSAGE_ALGORITHM:
        return
    if not all(isinstance(msg["payload"].get(field), str) and msg["payload"].get(field) for field in ["nonce", "ciphertext"]):
        return

    sender_key = get_sender_public_key(msg, state)
    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar mensagem de sessão de {sender}.")
        return
    if not verify_signature(canonical_message_bytes(online_session_message_signed_part(msg)), msg.get("signature"), sender_key):
        print(f"[AVISO] assinatura inválida de {sender} na mensagem de sessão {message_id}.")
        return

    with state.online_sessions_lock:
        session = state.online_sessions.get(sender)
        if not isinstance(session, dict) or session.get("session_id") != msg.get("session_id"):
            print(f"[AVISO] sessão online desconhecida para {sender}.")
            return
        counter = msg.get("counter")
        if not isinstance(counter, int) or counter <= int(session.get("recv_counter", 0)):
            print(f"[AVISO] contador repetido ou inválido na sessão com {sender}.")
            return
        session_key = session["session_key"]

    try:
        aad = build_online_session_aad(
            msg["session_id"],
            message_id,
            sender,
            msg["to"],
            msg["timestamp"],
            msg["counter"],
        )
        plaintext_raw = decrypt_online_session_message(session_key, msg["payload"], aad)
        plaintext_payload = parse_json_object(plaintext_raw)
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar mensagem de sessão {message_id}: {exc}")
        return

    if not isinstance(plaintext_payload, dict) or plaintext_payload.get("action") != GROUP_ACTION_MESSAGE:
        return
    text = plaintext_payload.get("text")
    if not isinstance(text, str):
        return

    if not save_to_history(state, msg, text):
        return

    with state.online_sessions_lock:
        session = state.online_sessions.get(sender)
        if isinstance(session, dict) and session.get("session_id") == msg.get("session_id"):
            session["recv_counter"] = msg["counter"]

    print(f"\n[Nova mensagem online] {sender}: {text} ({msg['timestamp']})")
