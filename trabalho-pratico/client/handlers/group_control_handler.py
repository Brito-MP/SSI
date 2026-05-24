from client_connection import send_request
from handlers.group_crypto_handler import group_control_plaintext
from handlers.group_rotation_handler import (
    get_group_rotation_leader,
    mark_group_key_rotation_pending,
    rotate_group_key,
    send_group_key_shares,
)
from handlers.group_sync_handler import update_groups
from handlers.message_common import GROUP_ROTATION_LEADER_FIELD, GROUP_ROTATION_PENDING_FIELD
from handlers.private_message_handler import build_message_envelope, get_user_key


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
