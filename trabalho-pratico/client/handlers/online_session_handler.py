import json
import time

from client_connection import send_request
from crypto_utils import (
    ONLINE_SESSION_MESSAGE_ALGORITHM,
    ONLINE_SESSION_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_VERSION,
    SESSION_INIT_TYPE,
    SESSION_RESPONSE_TYPE,
    build_online_session_aad,
    build_session_handshake_signing_data,
    canonical_message_bytes,
    decrypt_online_session_message,
    derive_online_session_key,
    encrypt_online_session_message,
    generate_message_id,
    generate_x25519_keypair,
    online_session_message_signed_part,
    public_key_to_pem,
    sign_message,
    utc_timestamp,
    verify_session_ephemeral_signature,
    verify_signature,
    x25519_public_key_from_pem,
)
from handlers.conversation_handler import save_to_history
from handlers.message_common import GROUP_ACTION_MESSAGE, parse_json_object
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

def get_online_session_winning_initiator(username, peer):
    if not isinstance(username, str) or not isinstance(peer, str):
        return None
    participants = sorted({username, peer})
    if len(participants) != 2:
        return None
    return participants[0]

def session_initiator_from_role(username, peer, role):
    if role == "initiator":
        return username
    if role == "responder":
        return peer
    return None

def session_record_initiator(username, peer, session):
    if not isinstance(session, dict):
        return None
    initiator = session.get("initiator")
    if isinstance(initiator, str) and initiator:
        return initiator
    return session_initiator_from_role(username, peer, session.get("role"))

def should_accept_session_init(state, sender, session_id):
    preferred_initiator = get_online_session_winning_initiator(state.username, sender)
    with state.online_sessions_lock:
        existing_session = state.online_sessions.get(sender)
        if isinstance(existing_session, dict):
            if existing_session.get("session_id") == session_id:
                return False
            existing_initiator = session_record_initiator(state.username, sender, existing_session)
            if existing_initiator == preferred_initiator:
                return False
            if sender != preferred_initiator:
                return False

        pending_session = state.pending_online_sessions.get(sender)
        if isinstance(pending_session, dict):
            if pending_session.get("session_id") == session_id:
                return False
            if state.username == preferred_initiator:
                return False
            state.pending_online_sessions.pop(sender, None)

    return True

def store_online_session(
    state,
    peer,
    session_id,
    role,
    session_key,
    own_ephemeral_public_key,
    peer_ephemeral_public_key,
):
    initiator = session_initiator_from_role(state.username, peer, role)
    responder = peer if role == "initiator" else state.username if role == "responder" else None
    with state.online_sessions_lock:
        existing_session = state.online_sessions.get(peer)
        if isinstance(existing_session, dict) and existing_session.get("session_id") != session_id:
            preferred_initiator = get_online_session_winning_initiator(state.username, peer)
            existing_initiator = session_record_initiator(state.username, peer, existing_session)
            if existing_initiator == preferred_initiator and initiator != preferred_initiator:
                return False
            if existing_initiator == initiator:
                return False

        state.online_sessions[peer] = {
            "session_id": session_id,
            "role": role,
            "initiator": initiator,
            "responder": responder,
            "session_key": session_key,
            "created_at": utc_timestamp(),
            "send_counter": 0,
            "recv_counter": 0,
            "peer_ephemeral_public_key": peer_ephemeral_public_key,
            "own_ephemeral_public_key": own_ephemeral_public_key,
        }
    return True

def wait_for_online_session(state, peer, session_id, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with state.online_sessions_lock:
            session = state.online_sessions.get(peer)
            if isinstance(session, dict) and session.get("session_id") == session_id:
                return session
        time.sleep(0.05)
    return None

def ensure_online_session(state, target):
    with state.online_sessions_lock:
        existing_session = state.online_sessions.get(target)
        if isinstance(existing_session, dict):
            return True
        pending_session = state.pending_online_sessions.get(target)
        pending_session_id = pending_session.get("session_id") if isinstance(pending_session, dict) else None

    if isinstance(pending_session_id, str) and pending_session_id:
        if wait_for_online_session(state, target, pending_session_id) is not None:
            return True
        print(f"Sessão E2EE online com {target} ainda está pendente.")
        return False

    ephemeral_private_key, ephemeral_public_key = generate_x25519_keypair()
    ephemeral_public_key_pem = public_key_to_pem(ephemeral_public_key)
    session_id = generate_message_id()
    init_envelope = build_session_handshake_envelope(
        SESSION_INIT_TYPE,
        session_id,
        state.username,
        target,
        ephemeral_public_key_pem,
        state.private_key,
    )

    with state.online_sessions_lock:
        state.pending_online_sessions[target] = {
            "session_id": session_id,
            "ephemeral_private_key": ephemeral_private_key,
            "own_ephemeral_public_key": ephemeral_public_key_pem,
            "created_at": utc_timestamp(),
        }

    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "send_message", **init_envelope},
    )

    if resp is None:
        with state.online_sessions_lock:
            state.pending_online_sessions.pop(target, None)
        print("Ligação perdida ao iniciar sessão E2EE online.")
        return False

    if resp.get("status") != "ok":
        with state.online_sessions_lock:
            state.pending_online_sessions.pop(target, None)
        print(resp.get("message", "erro ao iniciar sessão E2EE online"))
        return False

    if wait_for_online_session(state, target, session_id) is not None:
        return True

    print(f"Sessão E2EE online iniciada com {target}; a aguardar resposta de sessão.")
    return False

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
