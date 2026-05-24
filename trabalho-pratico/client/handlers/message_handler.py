import sys
import re
import json
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from crypto_utils import (
    build_group_aad,
    build_message_aad,
    canonical_message_bytes,
    decrypt_group_payload,
    decrypt_from_sender,
    decrypt_online_session_message,
    e2ee_public_key_binding_bytes,
    encrypt_online_session_message,
    encrypt_group_payload,
    encrypt_for_recipient,
    encrypt_for_recipient_v2,
    generate_group_key,
    generate_message_id,
    generate_x25519_keypair,
    GROUP_KEY_SHARE_TYPE,
    GROUP_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_ALGORITHM,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_VERSION,
    ONLINE_SESSION_MESSAGE_ALGORITHM,
    ONLINE_SESSION_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_VERSION,
    SESSION_INIT_TYPE,
    SESSION_RESPONSE_TYPE,
    build_online_session_aad,
    build_session_handshake_signing_data,
    derive_online_session_key,
    group_message_signed_part,
    offline_prekey_message_signed_part,
    online_session_message_signed_part,
    is_valid_group_key,
    normalize_group_key_version,
    normalize_groups,
    decrypt_from_signed_prekey,
    encrypt_for_signed_prekey,
    protect_groups,
    public_key_from_pem,
    public_key_to_pem,
    sign_message,
    unprotect_groups,
    utc_timestamp,
    verify_session_ephemeral_signature,
    verify_signature,
    x25519_public_key_from_pem,
)
from client_connection import send_request
from protocol import send_json
from common.certificates import certificate_from_pem, load_ca_certificate
from common.security import client_username_from_certificate, validate_certificate
from handlers.conversation_handler import save_to_history
from handlers.prekey_handler import get_recipient_signed_prekey, load_private_prekey, mark_prekey_used

GROUP_ACTION_DELETE = "delete"
GROUP_ACTION_LEAVE = "leave"
GROUP_ACTION_MESSAGE = "message"
GROUP_ACTION_KEY_ROTATION = "key_rotation"
GROUP_CONTROL_TYPE = "group_control"
GROUP_ROTATION_PENDING_FIELD = "group_key_rotation_pending"
GROUP_ROTATION_LEADER_FIELD = "group_key_rotation_leader"


def group_id_from_name(name: str):
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    slug = slug.strip("-")
    if not slug:
        return None
    return f"group-{slug}"


def _identity_key(recipient_keys):
    if isinstance(recipient_keys, dict):
        return recipient_keys.get("identity_public_key")
    return recipient_keys


def _e2ee_key(recipient_keys):
    if isinstance(recipient_keys, dict):
        return recipient_keys.get("e2ee_public_key")
    return None


def build_message_envelope(my_username, target, text, my_private_key, recipient_keys, group=None, group_action=None):
    message_id = generate_message_id()
    timestamp = utc_timestamp()
    aad = build_message_aad(message_id, my_username, target, timestamp)
    target_e2ee_public_key = _e2ee_key(recipient_keys)
    if target_e2ee_public_key is not None:
        payload = encrypt_for_recipient_v2(text, target_e2ee_public_key, aad)
    else:
        payload = encrypt_for_recipient(text, _identity_key(recipient_keys), aad)

    envelope_to_sign = {
        "message_id": message_id,
        "timestamp": timestamp,
        "from": my_username,
        "to": target,
        "payload": payload,
    }
    if group is not None:
        envelope_to_sign.update({
            "group_id": group["id"],
        })

    signature = sign_message(canonical_message_bytes(envelope_to_sign), my_private_key)

    return {
        **envelope_to_sign,
        "signature": signature,
    }


def build_offline_prekey_message_envelope(my_username, target, text, my_private_key, recipient_prekey):
    message_id = generate_message_id()
    timestamp = utc_timestamp()
    encrypted = encrypt_for_signed_prekey(
        text,
        recipient_prekey,
        my_username,
        target,
        message_id,
        timestamp,
    )
    envelope_to_sign = {
        "type": OFFLINE_PREKEY_MESSAGE_TYPE,
        "version": OFFLINE_PREKEY_MESSAGE_VERSION,
        "algorithm": OFFLINE_PREKEY_MESSAGE_ALGORITHM,
        "message_id": message_id,
        "timestamp": timestamp,
        "from": my_username,
        "to": target,
        "prekey_id": encrypted["prekey_id"],
        "ephemeral_public_key": encrypted["ephemeral_public_key"],
        "payload": encrypted["payload"],
    }
    signature = sign_message(canonical_message_bytes(offline_prekey_message_signed_part(envelope_to_sign)), my_private_key)
    return {
        **envelope_to_sign,
        "signature": signature,
    }


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


def parse_json_object(text):
    try:
        data = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def get_sender_public_key(msg, state):
    sender = msg["from"]

    if msg.get("sender_public_key") and msg.get("sender_certificate"):
        try:
            parsed_key = public_key_from_pem(msg["sender_public_key"])
            cert = certificate_from_pem(msg["sender_certificate"])
            ca_cert = load_ca_certificate()
            if not validate_certificate(cert, ca_cert, client_or_server=0):
                return None
            if client_username_from_certificate(cert) != sender:
                return None
            if public_key_to_pem(parsed_key) != public_key_to_pem(cert.public_key()):
                return None
            with state.key_cache_lock:
                state.key_cache[sender] = parsed_key
        except Exception:
            pass

    with state.key_cache_lock:
        return state.key_cache.get(sender)


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


def process_incoming_offline_prekey_message(msg, state, message_id):
    required_fields = [
        "type",
        "algorithm",
        "timestamp",
        "from",
        "to",
        "prekey_id",
        "ephemeral_public_key",
        "payload",
        "signature",
    ]
    for required_field in required_fields:
        if required_field == "payload":
            if not isinstance(msg.get(required_field), dict):
                return
            continue
        if not isinstance(msg.get(required_field), str) or not msg.get(required_field):
            return
    if msg.get("version") != OFFLINE_PREKEY_MESSAGE_VERSION:
        return
    if msg.get("algorithm") != OFFLINE_PREKEY_MESSAGE_ALGORITHM:
        return
    if msg.get("to") != state.username:
        return
    if not all(isinstance(msg["payload"].get(field), str) and msg["payload"].get(field) for field in ["nonce", "ciphertext"]):
        return

    sender = msg.get("from")
    sender_key = get_sender_public_key(msg, state)
    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar assinatura de {sender}.")
        return

    valid = verify_signature(
        canonical_message_bytes(offline_prekey_message_signed_part(msg)),
        msg["signature"],
        sender_key,
    )
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem offline {message_id}.")
        return

    prekey_id = msg["prekey_id"]
    try:
        private_prekey = load_private_prekey(state, prekey_id)
        plaintext = decrypt_from_signed_prekey(
            msg["payload"],
            private_prekey,
            msg["ephemeral_public_key"],
            prekey_id,
            sender,
            msg["to"],
            message_id,
            msg["timestamp"],
        )
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar mensagem offline {message_id}: {exc}")
        return

    if not save_to_history(state, msg, plaintext):
        return

    try:
        mark_prekey_used(state, prekey_id)
    except Exception as exc:
        print(f"[AVISO] mensagem decifrada, mas a prekey {prekey_id} não foi marcada como usada: {exc}")

    print(f"\n[Nova mensagem offline] {sender}: {plaintext} ({msg['timestamp']})")


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


def handle_group_key_share_message(state, msg, payload, message_id):
    group_id = payload.get("group_id")
    if not isinstance(group_id, str) or not group_id:
        return

    clean_groups = normalize_groups({
        group_id: {
            "name": payload.get("group_name", group_id),
            "members": payload.get("members", []),
            "group_key": payload.get("group_key"),
            "group_key_version": payload.get("group_key_version"),
        }
    })
    group = clean_groups.get(group_id)
    if group is None or not is_valid_group_key(group.get("group_key")):
        return

    sender = msg.get("from")
    members = group.get("members", [])
    if state.username not in members or sender not in members:
        print(f"[AVISO] partilha de group_key inválida para {group_id}.")
        return

    if not state.mark_message_seen(message_id):
        return

    state.groups_deleted.discard(group_id)
    existing_group = state.groups.get(group_id)
    existing_version = normalize_group_key_version(existing_group.get("group_key_version")) if isinstance(existing_group, dict) else 0
    received_version = normalize_group_key_version(group.get("group_key_version"))
    if received_version < existing_version:
        print(f"[AVISO] group_key antiga ignorada para {group_id}.")
        return
    if isinstance(existing_group, dict):
        expected_leader = existing_group.get(GROUP_ROTATION_LEADER_FIELD) if existing_group.get(GROUP_ROTATION_PENDING_FIELD) is True else None
        if isinstance(expected_leader, str) and expected_leader and sender != expected_leader:
            print(f"[AVISO] partilha de group_key ignorada para {group_id}: aguardava {expected_leader}.")
            return
        existing_key = existing_group.get("group_key")
        if received_version == existing_version and is_valid_group_key(existing_key) and existing_key != group.get("group_key"):
            print(f"[AVISO] group_key concorrente ignorada para {group_id}.")
            return

    state.groups[group_id] = group
    state.groups_dirty = True
    state.conversations.setdefault(group_id, [])
    print(f"\n[Grupo] Entraste no grupo {group.get('name', group_id)}.")


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


def handle_group_delete_message(state, msg, payload):
    group_id = payload.get("group_id") or msg.get("group_id")
    sender = msg.get("from")
    if not isinstance(group_id, str) or not group_id:
        return

    existing_group = state.groups.get(group_id)
    if existing_group is not None:
        members = existing_group.get("members", [])
        if isinstance(members, list) and sender not in members:
            print(f"[AVISO] {sender} tentou remover um grupo onde não é membro: {group_id}.")
            return

    removed_group = state.groups.pop(group_id, None)
    state.groups_deleted.add(group_id)
    state.groups_dirty = True

    if state.active_conversation == group_id:
        state.active_conversation = None

    group_name = payload.get("group_name", group_id)
    if removed_group is not None:
        group_name = removed_group.get("name", group_name)
    plaintext = payload.get("text", "")
    print(f"\n[Grupo removido] {group_name}: {plaintext}")


def handle_group_leave_message(state, msg, payload):
    group_id = payload.get("group_id") or msg.get("group_id")
    leaving_user = msg.get("from")
    if not isinstance(group_id, str) or not group_id:
        return

    group = state.groups.get(group_id)
    if not isinstance(group, dict):
        return

    members = sorted(set(group.get("members", [])))
    if leaving_user not in members or state.username not in members:
        return

    remaining_members = sorted(member for member in members if member != leaving_user)
    if state.username not in remaining_members:
        return

    rotation_leader = get_group_rotation_leader(remaining_members)
    if rotation_leader is None:
        return

    group["members"] = remaining_members
    if state.username == rotation_leader:
        state.groups[group_id] = rotate_group_key(group)
    else:
        state.groups[group_id] = mark_group_key_rotation_pending(group, rotation_leader)
    state.groups_dirty = True
    updated = update_groups(state)
    if updated and state.username == rotation_leader:
        send_group_key_shares(state, group_id)

    plaintext = payload.get("text", "")
    print(f"\n[Grupo] {leaving_user} saiu de {group.get('name', group_id)}: {plaintext}")
    if state.username != rotation_leader:
        print(f"[Grupo] A aguardar rotação da group_key de {group_id} por {rotation_leader}.")


def rotate_group_key(group):
    old_version = normalize_group_key_version(group.get("group_key_version"))
    group["group_key"] = generate_group_key()
    group["group_key_version"] = old_version + 1
    group.pop(GROUP_ROTATION_PENDING_FIELD, None)
    group.pop(GROUP_ROTATION_LEADER_FIELD, None)
    return group


def get_group_rotation_leader(group_or_members):
    if isinstance(group_or_members, dict):
        members = group_or_members.get("members", [])
    else:
        members = group_or_members
    clean_members = sorted({member.strip() for member in members if isinstance(member, str) and member.strip()})
    if not clean_members:
        return None
    return clean_members[0]


def mark_group_key_rotation_pending(group, rotation_leader):
    old_version = normalize_group_key_version(group.get("group_key_version"))
    group.pop("group_key", None)
    group["group_key_version"] = old_version + 1
    group[GROUP_ROTATION_PENDING_FIELD] = True
    group[GROUP_ROTATION_LEADER_FIELD] = rotation_leader
    return group


def get_user_key(state, target):
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

    certificate_pem = resp.get("certificate")
    if not isinstance(certificate_pem, str):
        print(f"Certificado de {target} em falta.")
        return None

    try:
        cert = certificate_from_pem(certificate_pem)
        ca_cert = load_ca_certificate()
        if not validate_certificate(cert, ca_cert, client_or_server=0):
            print(f"Certificado de {target} inválido.")
            return None

        cert_username = client_username_from_certificate(cert)
        if cert_username != target:
            print(f"Certificado recebido não pertence a {target}.")
            return None

        key = public_key_from_pem(resp["public_key"])
        cert_key_pem = public_key_to_pem(cert.public_key())
        received_key_pem = public_key_to_pem(key)
        if received_key_pem != cert_key_pem:
            print(f"Chave pública de {target} não corresponde ao certificado.")
            return None

        e2ee_key = None
        e2ee_key_pem = resp.get("e2ee_public_key")
        if isinstance(e2ee_key_pem, str):
            e2ee_signature = resp.get("e2ee_public_key_signature")
            if not isinstance(e2ee_signature, str):
                print(f"Assinatura da chave pública E2EE de {target} em falta.")
                return None
            if not verify_signature(e2ee_public_key_binding_bytes(target, e2ee_key_pem), e2ee_signature, key):
                print(f"Assinatura da chave pública E2EE de {target} inválida.")
                return None
            e2ee_key = x25519_public_key_from_pem(e2ee_key_pem)
    except Exception as exc:
        print(f"Erro ao validar chave pública de {target}: {exc}")
        return None

    with state.key_cache_lock:
        state.key_cache[target] = key
        if e2ee_key is not None:
            state.e2ee_key_cache[target] = e2ee_key
    return {
        "identity_public_key": key,
        "e2ee_public_key": e2ee_key,
        "online": bool(resp.get("online")),
    }


def sync_groups(state):
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "list_groups"},
    )

    if resp is None:
        print("Ligação perdida ao sincronizar grupos.")
        return False

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao sincronizar grupos"))
        return False

    protected_groups = resp.get("protected_groups")
    if protected_groups is not None:
        try:
            remote_groups = unprotect_groups(
                protected_groups,
                state.username,
                state.private_key,
                state.public_key,
            )
        except Exception as exc:
            print(f"[AVISO] grupos protegidos inválidos: {exc}")
            return False

        if state.groups_dirty:
            for deleted_group_id in state.groups_deleted:
                remote_groups.pop(deleted_group_id, None)
            state.groups = normalize_groups({**remote_groups, **state.groups})
            return update_groups(state)

        state.groups = remote_groups
        state.groups_deleted.clear()
        state.groups_dirty = False
        return True

    for deleted_group_id in state.groups_deleted:
        state.groups.pop(deleted_group_id, None)
    state.groups = normalize_groups(state.groups)
    return update_groups(state)


def update_groups(state):
    state.groups = normalize_groups(state.groups)
    protected_groups = protect_groups(
        state.username,
        state.groups,
        state.private_key,
        state.public_key,
    )
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {
            "command": "update_groups",
            "protected_groups": protected_groups,
        },
    )

    if resp is None:
        print("Ligação perdida ao atualizar grupos.")
        state.groups_dirty = True
        return False

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao atualizar grupos"))
        state.groups_dirty = True
        return False

    protected_groups = resp.get("protected_groups")
    if protected_groups is not None:
        try:
            state.groups = unprotect_groups(
                protected_groups,
                state.username,
                state.private_key,
                state.public_key,
            )
        except Exception as exc:
            print(f"[AVISO] servidor guardou grupos inválidos: {exc}")
            state.groups_dirty = True
            return False

    state.groups_dirty = False
    state.groups_deleted.clear()
    return True


def send_group_key_share(state, member, group_id, group):
    target_public_key = get_user_key(state, member)
    if target_public_key is None:
        return False

    plaintext = group_key_share_plaintext(group_id, group)
    envelope = build_message_envelope(
        state.username,
        member,
        plaintext,
        state.private_key,
        target_public_key,
    )
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "send_message", **envelope},
    )
    return resp is not None and resp.get("status") == "ok"


def send_group_key_shares(state, group_id):
    group = state.groups[group_id]
    failed_members = []
    for member in sorted({member for member in group.get("members", []) if member != state.username}):
        if not send_group_key_share(state, member, group_id, group):
            failed_members.append(member)
    return failed_members


def cmd_send(state, target, text):
    if target in state.groups:
        cmd_send_group(state, target, text)
        return

    target_public_key = get_user_key(state, target)
    if target_public_key is None:
        return

    if target_public_key.get("online") is True:
        if not ensure_online_session(state, target):
            return
        envelope = build_online_session_message_envelope(state, target, text)
        if envelope is None:
            print(f"Sem sessão E2EE online ativa com {target}; mensagem não enviada.")
            return
    else:
        signed_prekey = get_recipient_signed_prekey(
            state,
            target,
            target_public_key["identity_public_key"],
        )
        if signed_prekey is None:
            print(f"Sem signed prekey disponível para {target}; mensagem offline não enviada.")
            return
        envelope = build_offline_prekey_message_envelope(
            state.username,
            target,
            text,
            state.private_key,
            signed_prekey,
        )

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


def cmd_create_group(state, name, members):
    from handlers.contact_handler import sync_contacts

    sync_contacts(state)
    sync_groups(state)
    clean_name = name.strip()
    clean_members = sorted({member.strip() for member in members if member.strip()})
    if not clean_name:
        print("Nome do grupo inválido.")
        return

    if not clean_members:
        print("Um grupo precisa de pelo menos um contacto.")
        return

    missing_contacts = [member for member in clean_members if member not in state.contacts]
    if missing_contacts:
        print("Não podes criar grupos com o(s) contacto(s):", ", ".join(missing_contacts))
        return

    for member in clean_members:
        if get_user_key(state, member) is None:
            return

    all_members = sorted(set(clean_members + [state.username]))
    group_id = group_id_from_name(clean_name)
    if group_id is None:
        print("Nome do grupo inválido.")
        return

    if group_id in state.groups:
        print(f"Já existe um grupo com esse nome: {group_id}")
        return

    state.groups_deleted.discard(group_id)
    state.groups[group_id] = {
        "name": clean_name,
        "members": all_members,
        "group_key": generate_group_key(),
        "group_key_version": 1,
    }
    state.groups_dirty = True
    if not update_groups(state):
        state.groups.pop(group_id, None)
        return

    failed_members = send_group_key_shares(state, group_id)
    state.conversations.setdefault(group_id, [])
    if failed_members:
        print(f"Grupo '{clean_name}' criado, mas não foi possível partilhar a chave com:", ", ".join(failed_members))
    else:
        print(f"Grupo '{clean_name}' criado: {group_id}")


def cmd_groups(state):
    sync_groups(state)
    if not state.groups:
        print("Sem grupos.")
        return

    print("Grupos:")
    for group_id, group in sorted(state.groups.items(), key=lambda item: item[1].get("name", item[0])):
        members = ", ".join(group.get("members", []))
        print(f"- {group.get('name', group_id)} ({group_id}) [{members}]")


def cmd_remove_group(state, group_id):
    sync_groups(state)

    if group_id not in state.groups:
        print(f"{group_id} não é um grupo conhecido.")
        return

    removed_group = state.groups[group_id]
    members = sorted({member for member in removed_group.get("members", []) if member != state.username})
    group_info = {
        "id": group_id,
        "name": removed_group.get("name", group_id),
        "members": sorted(set(removed_group.get("members", []) + [state.username])),
    }
    failed_members = []

    for member in members:
        if not send_group_control_message(
            state,
            member,
            group_info,
            f"Grupo '{group_info['name']}' removido por {state.username}.",
            GROUP_ACTION_DELETE,
        ):
            failed_members.append(member)

    removed_group = state.groups.pop(group_id)
    state.groups_deleted.add(group_id)
    state.groups_dirty = True
    if not update_groups(state):
        state.groups[group_id] = removed_group
        state.groups_deleted.discard(group_id)
        return

    if state.active_conversation == group_id:
        state.active_conversation = None

    if failed_members:
        print("Grupo removido localmente, mas não foi possível notificar:", ", ".join(failed_members))
    else:
        print(f"Grupo '{removed_group.get('name', group_id)}' removido para todos os membros.")


def send_group_control_message(state, member, group_info, text, group_action):
    target_public_key = get_user_key(state, member)
    if target_public_key is None:
        return False

    plaintext = group_control_plaintext(group_info, text, group_action)
    envelope = build_message_envelope(
        state.username,
        member,
        plaintext,
        state.private_key,
        target_public_key,
        group=group_info,
    )
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "send_message", **envelope},
    )
    return resp is not None and resp.get("status") == "ok"


def cmd_remove_group_member(state, group_id, member):
    sync_groups(state)

    group = state.groups.get(group_id)
    if group is None:
        print(f"{group_id} não é um grupo conhecido.")
        return

    members = sorted(set(group.get("members", [])))
    if state.username not in members:
        print("Não pertences a esse grupo.")
        return
    if member == state.username:
        print("Usa leave_group para sair do grupo.")
        return
    if member not in members:
        print(f"{member} não pertence ao grupo.")
        return
    if len(members) <= 2:
        print("Remove o grupo se só resta um membro.")
        return

    old_group = dict(group)
    remaining_members = sorted(user for user in members if user != member)
    group["members"] = remaining_members
    rotate_group_key(group)
    state.groups[group_id] = group
    state.groups_dirty = True

    if not update_groups(state):
        state.groups[group_id] = old_group
        return

    group_info = {
        "id": group_id,
        "name": group.get("name", group_id),
        "members": members,
    }
    failed = []
    if not send_group_control_message(
        state,
        member,
        group_info,
        f"Foste removido do grupo '{group_info['name']}' por {state.username}.",
        GROUP_ACTION_DELETE,
    ):
        failed.append(member)

    failed.extend(send_group_key_shares(state, group_id))
    if failed:
        print("Membro removido e chave rodada, mas houve falhas ao notificar:", ", ".join(sorted(set(failed))))
    else:
        print(f"{member} removido de {group.get('name', group_id)}; group_key rodada para versão {group['group_key_version']}.")


def cmd_leave_group(state, group_id):
    sync_groups(state)

    group = state.groups.get(group_id)
    if group is None:
        print(f"{group_id} não é um grupo conhecido.")
        return

    members = sorted(set(group.get("members", [])))
    if state.username not in members:
        print("Não pertences a esse grupo.")
        return

    group_info = {
        "id": group_id,
        "name": group.get("name", group_id),
        "members": members,
    }
    failed = []
    for member in sorted(user for user in members if user != state.username):
        if not send_group_control_message(
            state,
            member,
            group_info,
            f"{state.username} saiu do grupo '{group_info['name']}'.",
            GROUP_ACTION_LEAVE,
        ):
            failed.append(member)

    removed_group = state.groups.pop(group_id)
    state.groups_deleted.add(group_id)
    state.groups_dirty = True
    if not update_groups(state):
        state.groups[group_id] = removed_group
        state.groups_deleted.discard(group_id)
        return

    if state.active_conversation == group_id:
        state.active_conversation = None

    if failed:
        print("Saíste do grupo localmente, mas houve falhas ao notificar:", ", ".join(failed))
    else:
        print(f"Saíste de {removed_group.get('name', group_id)}.")


def cmd_send_group(state, group_id, text):
    if group_id not in state.groups:
        sync_groups(state)

    group = state.groups.get(group_id)
    if group is None:
        print("Grupo desconhecido.")
        return

    if group.get(GROUP_ROTATION_PENDING_FIELD) is True:
        rotation_leader = group.get(GROUP_ROTATION_LEADER_FIELD, "outro membro")
        print(f"A aguardar rotação da group_key de {group_id} por {rotation_leader}; sincroniza depois de receberes a nova chave.")
        return

    if not is_valid_group_key(group.get("group_key")):
        print("Grupo sem group_key, recrie o grupo.")
        return

    members = sorted({member for member in group.get("members", []) if member != state.username})
    if not members:
        print("Grupo sem outros membros.")
        return

    sent = 0
    message_id = generate_message_id()
    timestamp = utc_timestamp()
    payload = build_group_message_payload(state.username, group_id, group, text, message_id, timestamp)

    for member in members:
        aad = build_group_aad(group_id, state.username, member, message_id, timestamp)
        encrypted_payload = encrypt_group_payload(group["group_key"], payload, aad)
        envelope = build_group_message_envelope(
            state.username,
            member,
            group_id,
            encrypted_payload,
            message_id,
            timestamp,
            state.private_key,
        )
        resp = send_request(
            state.sock,
            state.response_queue,
            state.stop_event,
            {"command": "send_message", **envelope},
        )

        if resp is None:
            print(f"Ligação perdida ao enviar para {member}.")
            continue

        if resp.get("status") != "ok":
            print(f"{member}: {resp.get('message', 'erro ao enviar mensagem')}")
            continue

        sent += 1

    if sent == 0:
        print("Mensagem de grupo não foi enviada.")
        return

    local_envelope = {
        "message_id": message_id,
        "timestamp": timestamp,
        "from": state.username,
        "to": group_id,
        "group_id": group_id,
        "group_name": group.get("name", group_id),
        "group_members": group.get("members", []),
        "group_key_version": normalize_group_key_version(group.get("group_key_version")),
    }
    save_to_history(state, local_envelope, text)
    print(f"Mensagem enviada para {sent} membro(s) do grupo.")


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
