from client_connection import send_request
from crypto_utils import normalize_groups, protect_groups, unprotect_groups


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
