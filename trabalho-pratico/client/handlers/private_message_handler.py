from handlers.message_common import ROOT_DIR
from client_connection import send_request
from common.certificates import certificate_from_pem, load_ca_certificate
from common.security import client_username_from_certificate, validate_certificate
from crypto_utils import (
    build_message_aad,
    canonical_message_bytes,
    e2ee_public_key_binding_bytes,
    encrypt_for_recipient,
    encrypt_for_recipient_v2,
    generate_message_id,
    public_key_from_pem,
    public_key_to_pem,
    sign_message,
    utc_timestamp,
    verify_signature,
    x25519_public_key_from_pem,
)
from handlers.conversation_handler import save_to_history
from handlers.prekey_handler import get_recipient_signed_prekey


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

def cmd_send(state, target, text):
    if target in state.groups:
        from handlers.group_message_handler import cmd_send_group

        cmd_send_group(state, target, text)
        return

    target_public_key = get_user_key(state, target)
    if target_public_key is None:
        return

    if target_public_key.get("online") is True:
        from handlers.online_session_handler import build_online_session_message_envelope, ensure_online_session

        if not ensure_online_session(state, target):
            return
        envelope = build_online_session_message_envelope(state, target, text)
        if envelope is None:
            print(f"Sem sessão E2EE online ativa com {target}; mensagem não enviada.")
            return
    else:
        from handlers.offline_message_handler import build_offline_prekey_message_envelope

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
