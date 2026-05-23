import sys
import re
import json
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from crypto_utils import (
    build_message_aad,
    canonical_message_bytes,
    decrypt_group_payload,
    decrypt_from_sender,
    e2ee_public_key_binding_bytes,
    encrypt_group_payload,
    encrypt_for_recipient,
    encrypt_for_recipient_v2,
    generate_group_key,
    generate_message_id,
    GROUP_KEY_SHARE_TYPE,
    GROUP_MESSAGE_TYPE,
    group_message_signed_part,
    is_valid_group_key,
    normalize_group_key_version,
    normalize_groups,
    protect_groups,
    public_key_from_pem,
    public_key_to_pem,
    sign_message,
    unprotect_groups,
    utc_timestamp,
    verify_signature,
    x25519_public_key_from_pem,
)
from client_connection import send_request
from common.certificates import certificate_from_pem, load_ca_certificate
from common.security import client_username_from_certificate, validate_certificate
from handlers.conversation_handler import save_to_history

GROUP_ACTION_DELETE = "delete"
GROUP_ACTION_LEAVE = "leave"


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
            "group_name": group["name"],
            "group_members": group["members"],
        })
    if group_action is not None:
        envelope_to_sign["group_action"] = group_action

    signature = sign_message(canonical_message_bytes(envelope_to_sign), my_private_key)

    return {
        **envelope_to_sign,
        "signature": signature,
    }


def group_key_share_plaintext(group_id, group):
    payload = {
        "type": GROUP_KEY_SHARE_TYPE,
        "group_id": group_id,
        "group_name": group.get("name", group_id),
        "members": sorted(set(group.get("members", []))),
        "group_key": group["group_key"],
        "group_key_version": normalize_group_key_version(group.get("group_key_version")),
    }
    return json.dumps(payload, separators=(",", ":"))


def build_group_message_payload(my_username, group_id, group, text, message_id, timestamp):
    return {
        "type": GROUP_MESSAGE_TYPE,
        "group_id": group_id,
        "group_name": group.get("name", group_id),
        "members": sorted(set(group.get("members", []))),
        "from": my_username,
        "text": text,
        "timestamp": timestamp,
        "message_id": message_id,
        "group_key_version": normalize_group_key_version(group.get("group_key_version")),
    }


def build_group_message_envelope(my_username, target, group_id, encrypted_payload, message_id, timestamp, my_private_key):
    envelope_to_sign = {
        "type": GROUP_MESSAGE_TYPE,
        "group_id": group_id,
        "group_key_version": encrypted_payload["group_key_version"],
        "message_id": message_id,
        "timestamp": timestamp,
        "from": my_username,
        "to": target,
        "nonce": encrypted_payload["nonce"],
        "ciphertext": encrypted_payload["ciphertext"],
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


def process_incoming_group_message(msg, state, message_id):
    required_fields = ["type", "group_id", "timestamp", "from", "to", "nonce", "ciphertext", "signature"]
    for required_field in required_fields:
        if not isinstance(msg.get(required_field), str) or not msg.get(required_field):
            return

    sender_key = get_sender_public_key(msg, state)
    sender = msg.get("from")
    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar assinatura de {sender}.")
        return

    valid = verify_signature(
        canonical_message_bytes(group_message_signed_part(msg)),
        msg["signature"],
        sender_key,
    )
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem de grupo {message_id}.")
        return

    group_id = msg["group_id"]
    group = state.groups.get(group_id)
    if not isinstance(group, dict) or not is_valid_group_key(group.get("group_key")):
        print(f"[AVISO] sem group_key local para decifrar mensagem do grupo {group_id}.")
        return
    msg_key_version = normalize_group_key_version(msg.get("group_key_version"))
    group_key_version = normalize_group_key_version(group.get("group_key_version"))
    if msg_key_version != group_key_version:
        print(f"[AVISO] sem group_key versão {msg_key_version} para decifrar mensagem do grupo {group_id}.")
        return

    try:
        aad = build_message_aad(message_id, sender, msg["to"], msg["timestamp"])
        payload = decrypt_group_payload(group["group_key"], msg["nonce"], msg["ciphertext"], aad)
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar a mensagem de grupo {message_id}: {exc}")
        return

    if payload.get("type") != GROUP_MESSAGE_TYPE:
        return
    if payload.get("group_id") != group_id or payload.get("message_id") != message_id:
        print(f"[AVISO] metadados inconsistentes na mensagem de grupo {message_id}.")
        return
    if normalize_group_key_version(payload.get("group_key_version")) != msg_key_version:
        print(f"[AVISO] versão da group_key inconsistente na mensagem de grupo {message_id}.")
        return
    if payload.get("from") != sender:
        print(f"[AVISO] remetente inconsistente na mensagem de grupo {message_id}.")
        return
    if not isinstance(payload.get("text"), str) or not isinstance(payload.get("timestamp"), str):
        return

    history_msg = {
        "message_id": message_id,
        "timestamp": payload["timestamp"],
        "from": sender,
        "to": group_id,
        "group_id": group_id,
        "group_name": payload.get("group_name", group.get("name", group_id)),
        "group_members": payload.get("members", group.get("members", [])),
    }

    if not save_to_history(state, history_msg, payload["text"]):
        return

    group_name = history_msg["group_name"]
    print(f"\n[Nova mensagem em {group_name}] {sender}: {payload['text']} ({payload['timestamp']})")


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

    state.groups[group_id] = group
    state.groups_dirty = True
    state.conversations.setdefault(group_id, [])
    print(f"\n[Grupo] Entraste no grupo {group.get('name', group_id)}.")


def process_incoming_message(msg, state):
    message_id = msg.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        return

    if state.has_seen_message(message_id):
        return

    if msg.get("type") == GROUP_MESSAGE_TYPE:
        process_incoming_group_message(msg, state, message_id)
        return

    for required_field in ["timestamp", "from", "to", "payload", "signature"]:
        if required_field not in msg:
            return

    sender_key = get_sender_public_key(msg, state)
    sender = msg.get("from")

    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar assinatura de {sender}.")
        return

    signed_part = {
        "message_id": message_id,
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
    }
    for optional_field in ["group_id", "group_name", "group_members", "group_action"]:
        if optional_field in msg:
            signed_part[optional_field] = msg[optional_field]

    valid = verify_signature(canonical_message_bytes(signed_part), msg["signature"], sender_key)
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem {msg.get('message_id')}.")
        return

    try:
        aad = build_message_aad(message_id, msg["from"], msg["to"], msg["timestamp"])
        plaintext = decrypt_from_sender(msg["payload"], state.private_key, state.x25519_private_key, aad)
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar a mensagem {msg.get('message_id')}: {exc}")
        return

    control_payload = parse_json_object(plaintext)
    if control_payload is not None and control_payload.get("type") == GROUP_KEY_SHARE_TYPE:
        handle_group_key_share_message(state, msg, control_payload, message_id)
        return

    if msg.get("group_action") == GROUP_ACTION_DELETE:
        if not state.mark_message_seen(message_id):
            return
        handle_group_delete_message(state, msg, plaintext)
        return

    if msg.get("group_action") == GROUP_ACTION_LEAVE:
        if not state.mark_message_seen(message_id):
            return
        handle_group_leave_message(state, msg, plaintext)
        return

    if not save_to_history(state, msg, plaintext):
        return

    if msg.get("group_id"):
        group_name = msg.get("group_name", msg["group_id"])
        print(f"\n[Nova mensagem em {group_name}] {sender}: {plaintext} ({msg['timestamp']})")
    else:
        print(f"\n[Nova mensagem] {sender}: {plaintext} ({msg['timestamp']})")


def handle_group_delete_message(state, msg, plaintext):
    group_id = msg.get("group_id")
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

    group_name = msg.get("group_name", group_id)
    if removed_group is not None:
        group_name = removed_group.get("name", group_name)
    print(f"\n[Grupo removido] {group_name}: {plaintext}")


def handle_group_leave_message(state, msg, plaintext):
    group_id = msg.get("group_id")
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

    group["members"] = remaining_members
    state.groups[group_id] = rotate_group_key(group)
    state.groups_dirty = True
    if update_groups(state) and state.username == remaining_members[0]:
        send_group_key_shares(state, group_id)

    print(f"\n[Grupo] {leaving_user} saiu de {group.get('name', group_id)}: {plaintext}")


def rotate_group_key(group):
    old_version = normalize_group_key_version(group.get("group_key_version"))
    group["group_key"] = generate_group_key()
    group["group_key_version"] = old_version + 1
    return group


def get_user_key(state, target):
    with state.key_cache_lock:
        if target in state.key_cache and target in state.e2ee_key_cache:
            return {
                "identity_public_key": state.key_cache[target],
                "e2ee_public_key": state.e2ee_key_cache.get(target),
            }

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
        target_public_key = get_user_key(state, member)
        if target_public_key is None:
            failed_members.append(member)
            continue

        envelope = build_message_envelope(
            state.username,
            member,
            f"Grupo '{group_info['name']}' removido por {state.username}.",
            state.private_key,
            target_public_key,
            group=group_info,
            group_action=GROUP_ACTION_DELETE,
        )
        resp = send_request(
            state.sock,
            state.response_queue,
            state.stop_event,
            {"command": "send_message", **envelope},
        )

        if resp is None or resp.get("status") != "ok":
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

    envelope = build_message_envelope(
        state.username,
        member,
        text,
        state.private_key,
        target_public_key,
        group=group_info,
        group_action=group_action,
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
        aad = build_message_aad(message_id, state.username, member, timestamp)
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
        if state.groups_dirty:
            update_groups(state)
        print("Sem mensagens pendentes.")
        return

    for msg in messages:
        process_incoming_message(msg, state)

    if state.groups_dirty:
        update_groups(state)

    print(f"Sincronização concluída: {len(messages)} mensagem(ns).")
