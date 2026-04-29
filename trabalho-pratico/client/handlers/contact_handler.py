from client_connection import send_request
from crypto_utils import normalize_contact_list, protect_contacts, unprotect_contacts
from handlers.message_handler import get_user_key


def sync_contacts(state):
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "list_contacts"},
    )

    if resp is None:
        print("Ligação perdida ao sincronizar contactos.")
        return False

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao sincronizar contactos"))
        return False

    protected_contacts = resp.get("protected_contacts")
    if protected_contacts is not None:
        try:
            state.contacts = set(unprotect_contacts(
                protected_contacts,
                state.username,
                state.private_key,
                state.public_key,
            ))
            return True
        except Exception as exc:
            print(f"[AVISO] contactos protegidos inválidos: {exc}")
            return False

    state.contacts = set()
    return update_contacts(state)


def update_contacts(state):
    protected_contacts = protect_contacts(
        state.username,
        state.contacts,
        state.private_key,
        state.public_key,
    )
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {
            "command": "update_contacts",
            "protected_contacts": protected_contacts,
        },
    )

    if resp is None:
        print("Ligação perdida ao atualizar contactos.")
        return False

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao atualizar contactos"))
        return False

    protected_contacts = resp.get("protected_contacts")
    if protected_contacts is not None:
        try:
            state.contacts = set(unprotect_contacts(
                protected_contacts,
                state.username,
                state.private_key,
                state.public_key,
            ))
        except Exception as exc:
            print(f"[AVISO] servidor guardou contactos inválidos: {exc}")
            return False

    state.contacts = set(normalize_contact_list(state.contacts))
    return True


def cmd_contacts(state):
    sync_contacts(state)
    if not state.contacts:
        print("Sem contactos.")
        return

    print("Contactos:")
    for contact in sorted(state.contacts):
        print(f"- {contact}")


def cmd_add_contact(state, target):
    sync_contacts(state)

    if target == state.username:
        print("Não podes adicionar o teu próprio utilizador.")
        return

    if target in state.contacts:
        print(f"{target} já está nos contactos.")
        return

    key = get_user_key(state, target)
    if key is None:
        return

    state.contacts.add(target)
    if not update_contacts(state):
        state.contacts.discard(target)
        return

    print(f"Contacto '{target}' adicionado.")


def cmd_remove_contact(state, target):
    sync_contacts(state)

    if target not in state.contacts:
        print(f"{target} não está nos contactos.")
        return

    state.contacts.remove(target)
    if not update_contacts(state):
        state.contacts.add(target)
        return

    if state.active_conversation == target:
        state.active_conversation = None

    print(f"Contacto '{target}' removido.")
