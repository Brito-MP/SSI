import json
import os
import tempfile
from pathlib import Path

from handlers.message_handler import get_user_key


ROOT_DIR = Path(__file__).resolve().parents[2]
CONTACTS_DIR = ROOT_DIR / "contacts"


def contacts_path(username: str) -> Path:
    return CONTACTS_DIR / f"{username}_contacts.json"


def load_contacts(username: str):
    path = contacts_path(username)
    if not path.exists():
        return set()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[AVISO] erro a ler contactos locais: {exc}")
        return set()

    if not isinstance(data, list):
        print("[AVISO] formato inválido no ficheiro de contactos local.")
        return set()

    contacts = set()
    for item in data:
        if isinstance(item, str):
            clean_item = item.strip()
            if clean_item:
                contacts.add(clean_item)

    return contacts


def save_contacts(username: str, contacts):
    CONTACTS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = contacts_path(username)

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(CONTACTS_DIR), delete=False) as tmp:
        json.dump(sorted(contacts), tmp, indent=2, ensure_ascii=False)
        tmp_path = tmp.name

    os.replace(tmp_path, target_path)


def cmd_contacts(state):
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

    state.contacts.add(target)
    save_contacts(state.username, state.contacts)
    print(f"Contacto '{target}' adicionado.")
