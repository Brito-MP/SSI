from crypto_utils import (
    SESSION_RESPONSE_TYPE,
    build_session_handshake_signing_data,
    derive_online_session_key,
    generate_x25519_keypair,
    public_key_to_pem,
    sign_message,
    utc_timestamp,
    verify_session_ephemeral_signature,
    x25519_public_key_from_pem,
)
from handlers.online_session_state_handler import should_accept_session_init, store_online_session
from handlers.private_message_handler import get_sender_public_key
from protocol import send_json


def build_session_handshake_envelope(message_type, session_id, sender, target, ephemeral_public_key_pem, my_private_key):
    envelope_to_sign = {
        "type": message_type,
        "session_id": session_id,
        "message_id": session_id,
        "timestamp": utc_timestamp(),
        "from": sender,
        "to": target,
        "ephemeral_public_key": ephemeral_public_key_pem,
    }
    signature = sign_message(build_session_handshake_signing_data(envelope_to_sign), my_private_key)
    return {
        **envelope_to_sign,
        "signature": signature,
    }

def process_session_init_message(msg, state, message_id):
    sender = msg.get("from")
    if msg.get("to") != state.username or not isinstance(sender, str):
        return

    sender_key = get_sender_public_key(msg, state)
    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar sessão de {sender}.")
        return
    if not verify_session_ephemeral_signature(msg, sender_key):
        print(f"[AVISO] assinatura de sessão inválida de {sender}.")
        return

    if not should_accept_session_init(state, sender, msg.get("session_id")):
        state.mark_message_seen(message_id)
        print(f"[AVISO] session_init perdedor ignorado de {sender}.")
        return

    peer_ephemeral_public_key = x25519_public_key_from_pem(msg["ephemeral_public_key"])
    own_ephemeral_private_key, own_ephemeral_public_key = generate_x25519_keypair()
    own_ephemeral_public_key_pem = public_key_to_pem(own_ephemeral_public_key)
    shared_secret = own_ephemeral_private_key.exchange(peer_ephemeral_public_key)
    session_key = derive_online_session_key(
        shared_secret,
        msg["session_id"],
        sender,
        state.username,
        msg["ephemeral_public_key"],
        own_ephemeral_public_key_pem,
    )
    if not store_online_session(
        state,
        sender,
        msg["session_id"],
        "responder",
        session_key,
        own_ephemeral_public_key_pem,
        msg["ephemeral_public_key"],
    ):
        state.mark_message_seen(message_id)
        print(f"[AVISO] session_init não substituiu sessão vencedora com {sender}.")
        return
    state.mark_message_seen(message_id)

    response = build_session_handshake_envelope(
        SESSION_RESPONSE_TYPE,
        msg["session_id"],
        state.username,
        sender,
        own_ephemeral_public_key_pem,
        state.private_key,
    )
    try:
        send_json(state.sock, {"command": "relay_session_envelope", **response})
    except Exception as exc:
        print(f"[AVISO] sessão criada, mas resposta para {sender} falhou: {exc}")

def process_session_response_message(msg, state, message_id):
    sender = msg.get("from")
    if msg.get("to") != state.username or not isinstance(sender, str):
        return

    sender_key = get_sender_public_key(msg, state)
    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar sessão de {sender}.")
        return
    if not verify_session_ephemeral_signature(msg, sender_key):
        print(f"[AVISO] assinatura de sessão inválida de {sender}.")
        return

    with state.online_sessions_lock:
        pending = state.pending_online_sessions.get(sender)
        if not isinstance(pending, dict) or pending.get("session_id") != msg.get("session_id"):
            state.mark_message_seen(message_id)
            print(f"[AVISO] resposta de sessão inesperada de {sender}.")
            return
        own_ephemeral_private_key = pending["ephemeral_private_key"]
        own_ephemeral_public_key = pending["own_ephemeral_public_key"]

    peer_ephemeral_public_key = x25519_public_key_from_pem(msg["ephemeral_public_key"])
    shared_secret = own_ephemeral_private_key.exchange(peer_ephemeral_public_key)
    session_key = derive_online_session_key(
        shared_secret,
        msg["session_id"],
        state.username,
        sender,
        own_ephemeral_public_key,
        msg["ephemeral_public_key"],
    )
    with state.online_sessions_lock:
        pending = state.pending_online_sessions.get(sender)
        if isinstance(pending, dict) and pending.get("session_id") == msg.get("session_id"):
            del state.pending_online_sessions[sender]

    store_online_session(
        state,
        sender,
        msg["session_id"],
        "initiator",
        session_key,
        own_ephemeral_public_key,
        msg["ephemeral_public_key"],
    )
    state.mark_message_seen(message_id)
