from client_connection import send_request
from handlers.message_handler import get_user_key


def parse_contacts(data):
    if not isinstance(data, list):
        return set()
    contacts = set()
    for item in data:
        if isinstance(item, str):
            clean_item = item.strip()
            if clean_item:
                contacts.add(clean_item)

    return contacts


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

    state.contacts = parse_contacts(resp.get("contacts", []))
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
    if target == state.username:
        print("Não podes adicionar o teu próprio utilizador.")
        return

    if target in state.contacts:
        print(f"{target} já está nos contactos.")
        return

    key = get_user_key(state, target)
    if key is None:
        return

    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "add_contact", "target": target},
    )

    if resp is None:
        print("Ligação perdida ao adicionar contacto.")
        return

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao adicionar contacto"))
        return

    state.contacts = parse_contacts(resp.get("contacts", []))
    print(resp.get("message", f"Contacto '{target}' adicionado."))
