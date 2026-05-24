from client_connection import send_request
from crypto_utils import generate_group_key, is_valid_group_key, normalize_group_key_version, normalize_groups
from handlers.group_crypto_handler import group_key_share_plaintext
from handlers.private_message_handler import build_message_envelope, get_user_key
from handlers.message_common import GROUP_ROTATION_LEADER_FIELD, GROUP_ROTATION_PENDING_FIELD


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
