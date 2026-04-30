import sys
import re
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from crypto_utils import (
    canonical_message_bytes,
    decrypt_from_sender,
    encrypt_for_recipient,
    generate_message_id,
    normalize_groups,
    protect_groups,
    public_key_from_pem,
    public_key_to_pem,
    sign_message,
    unprotect_groups,
    utc_timestamp,
    verify_signature,
)
from client_connection import send_request
from common.certificates import certificate_from_pem, load_ca_certificate
from common.security import client_username_from_certificate, validate_certificate
from handlers.conversation_handler import save_to_history

GROUP_ACTION_DELETE = "delete"


def group_id_from_name(name: str):
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    slug = slug.strip("-")
    if not slug:
        return None
    return f"group-{slug}"


def build_message_envelope(my_username, target, text, my_private_key, target_public_key, group=None, group_action=None):
    payload = encrypt_for_recipient(text, target_public_key)

    envelope_to_sign = {
        "message_id": generate_message_id(),
        "timestamp": utc_timestamp(),
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
    for optional_field in ["group_id", "group_name", "group_members", "group_action"]:
        if optional_field in msg:
            signed_part[optional_field] = msg[optional_field]

    valid = verify_signature(canonical_message_bytes(signed_part), msg["signature"], sender_key)
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem {msg.get('message_id')}.")
        return

    try:
        plaintext = decrypt_from_sender(msg["payload"], state.private_key)
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar a mensagem {msg.get('message_id')}: {exc}")
        return

    if msg.get("group_action") == GROUP_ACTION_DELETE:
        handle_group_delete_message(state, msg, plaintext)
        return

    save_to_history(state, msg, plaintext)
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
    except Exception as exc:
        print(f"Erro ao validar chave pública de {target}: {exc}")
        return None

    with state.key_cache_lock:
        state.key_cache[target] = key
    return key


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
        print("Só podes criar grupos com contactos:", ", ".join(missing_contacts))
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
    }
    state.groups_dirty = True
    if not update_groups(state):
        state.groups.pop(group_id, None)
        return

    state.conversations.setdefault(group_id, [])
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


def cmd_send_group(state, group_id, text):
    if group_id not in state.groups:
        sync_groups(state)

    group = state.groups.get(group_id)
    if group is None:
        print("Grupo desconhecido.")
        return

    members = sorted({member for member in group.get("members", []) if member != state.username})
    if not members:
        print("Grupo sem outros membros.")
        return

    sent = 0
    local_envelope = None
    group_info = {
        "id": group_id,
        "name": group.get("name", group_id),
        "members": sorted(set(group.get("members", []) + [state.username])),
    }

    for member in members:
        target_public_key = get_user_key(state, member)
        if target_public_key is None:
            continue

        envelope = build_message_envelope(
            state.username,
            member,
            text,
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

        if resp is None:
            print(f"Ligação perdida ao enviar para {member}.")
            continue

        if resp.get("status") != "ok":
            print(f"{member}: {resp.get('message', 'erro ao enviar mensagem')}")
            continue

        sent += 1
        if local_envelope is None:
            local_envelope = {
                **envelope,
                "to": group_id,
            }

    if sent == 0:
        print("Mensagem de grupo não foi enviada.")
        return

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
