from client_connection import send_request
from crypto_utils import (
    build_group_aad,
    encrypt_group_payload,
    generate_group_key,
    generate_message_id,
    is_valid_group_key,
    normalize_group_key_version,
    utc_timestamp,
)
from handlers.conversation_handler import save_to_history
from handlers.group_control_handler import send_group_control_message
from handlers.group_crypto_handler import (
    build_group_message_envelope,
    build_group_message_payload,
    group_id_from_name,
)
from handlers.group_rotation_handler import rotate_group_key, send_group_key_shares
from handlers.group_sync_handler import sync_groups, update_groups
from handlers.message_common import (
    GROUP_ACTION_DELETE,
    GROUP_ACTION_LEAVE,
    GROUP_ROTATION_LEADER_FIELD,
    GROUP_ROTATION_PENDING_FIELD,
)
from handlers.private_message_handler import get_user_key


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
