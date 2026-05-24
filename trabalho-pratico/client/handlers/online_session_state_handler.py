import time

from client_connection import send_request
from crypto_utils import SESSION_INIT_TYPE, generate_message_id, generate_x25519_keypair, public_key_to_pem, utc_timestamp


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
    from handlers.online_session_handshake_handler import build_session_handshake_envelope

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
