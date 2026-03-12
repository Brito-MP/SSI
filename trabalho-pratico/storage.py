import json
import os


USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"


def _load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_users():
    return _load_json(USERS_FILE, {})


def save_users(users):
    _save_json(USERS_FILE, users)


def load_messages():
    return _load_json(MESSAGES_FILE, [])


def save_messages(messages):
    _save_json(MESSAGES_FILE, messages)