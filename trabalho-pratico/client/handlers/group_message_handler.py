import json
import re

from client_connection import send_request
from crypto_utils import (
    GROUP_KEY_SHARE_TYPE,
    GROUP_MESSAGE_TYPE,
    build_group_aad,
    canonical_message_bytes,
    decrypt_group_payload,
    encrypt_group_payload,
    generate_group_key,
    generate_message_id,
    group_message_signed_part,
    is_valid_group_key,
    normalize_group_key_version,
    normalize_groups,
    protect_groups,
    sign_message,
    unprotect_groups,
    utc_timestamp,
    verify_signature,
)
from handlers.conversation_handler import save_to_history
from handlers.message_common import (
    GROUP_ACTION_DELETE,
    GROUP_ACTION_KEY_ROTATION,
    GROUP_ACTION_LEAVE,
    GROUP_ACTION_MESSAGE,
    GROUP_CONTROL_TYPE,
    GROUP_ROTATION_LEADER_FIELD,
    GROUP_ROTATION_PENDING_FIELD,
)
from handlers.private_message_handler import build_message_envelope, get_sender_public_key, get_user_key


def group_id_from_name(name: str):
    slug = re.sub(r"[^a-z0-9]+", "-", name.strip().lower())
    slug = slug.strip("-")
    if not slug:
        return None
    return f"group-{slug}"

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
