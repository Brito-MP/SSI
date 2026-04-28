import json
import os
import tempfile


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
MESSAGES_FILE = os.path.join(BASE_DIR, "messages.json")
CONTACTS_FIELD = "contacts"


# Lê um ficheiro JSON e devolve um valor por omissão caso ainda não exista.
def _load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# Guarda JSON de forma atómica para reduzir o risco de corromper o ficheiro.
def _save_json(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, delete=False) as tmp:
        json.dump(data, tmp, indent=2, ensure_ascii=False)
        tmp_path = tmp.name

    os.replace(tmp_path, path)


def load_users():
    return _load_json(USERS_FILE, {})


def save_users(users):
    _save_json(USERS_FILE, users)


def normalize_contacts(user_data):
    contacts = user_data.get(CONTACTS_FIELD, [])
    if not isinstance(contacts, list):
        return []

    clean_contacts = set()
    for contact in contacts:
        if isinstance(contact, str):
            clean_contact = contact.strip()
            if clean_contact:
                clean_contacts.add(clean_contact)

    return sorted(clean_contacts)


def ensure_user_contacts(user_data):
    user_data[CONTACTS_FIELD] = normalize_contacts(user_data)
    return user_data[CONTACTS_FIELD]


def load_messages():
    return _load_json(MESSAGES_FILE, [])


# O servidor guarda apenas envelopes cifrados e metadados.
# Não deve guardar qualquer chave privada nem chaves simétricas em claro.
def save_messages(messages):
    _save_json(MESSAGES_FILE, messages)
