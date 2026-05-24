import json
import os
import tempfile
import threading
from contextlib import contextmanager

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")
MESSAGES_FILE = os.path.join(BASE_DIR, "messages.json")
PROTECTED_CONTACTS_FIELD = "protected_contacts"
PROTECTED_GROUPS_FIELD = "protected_groups"
_USERS_LOCK = threading.RLock()
_MESSAGES_LOCK = threading.RLock()


@contextmanager
def users_lock():
    with _USERS_LOCK:
        yield


@contextmanager
def messages_lock():
    with _MESSAGES_LOCK:
        yield


def _load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, delete=False) as tmp:
        tmp_path = tmp.name
        try:
            json.dump(data, tmp, indent=2, ensure_ascii=False)
            tmp.flush()
            os.fsync(tmp.fileno())
        except Exception:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise

    os.replace(tmp_path, path)


def load_users():
    with _USERS_LOCK:
        return _load_json(USERS_FILE, {})


def save_users(users):
    with _USERS_LOCK:
        _save_json(USERS_FILE, users)


def set_protected_contacts(user_data, protected_contacts):
    user_data[PROTECTED_CONTACTS_FIELD] = protected_contacts
    user_data.pop("contacts", None)


def set_protected_groups(user_data, protected_groups):
    user_data[PROTECTED_GROUPS_FIELD] = protected_groups
    user_data.pop("groups", None)


def load_messages():
    with _MESSAGES_LOCK:
        return _load_json(MESSAGES_FILE, [])


def save_messages(messages):
    with _MESSAGES_LOCK:
        _save_json(MESSAGES_FILE, messages)
