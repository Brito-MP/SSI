import json
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from client_connection import send_request
from crypto_utils import (
    SIGNED_PREKEY_ALGORITHM,
    SIGNED_PREKEY_TYPE,
    SIGNED_PREKEY_VERSION,
    generate_signed_prekey,
    private_key_to_pem,
    utc_timestamp,
    x25519_private_key_from_pem,
    verify_signed_prekey,
)

PREKEYS_DIR = ROOT_DIR / "keys"
_PREKEYS_LOCK = threading.RLock()


def _write_json_file(path, data):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, delete=False) as tmp:
        tmp_path = tmp.name
        try:
            json.dump(data, tmp, indent=2, ensure_ascii=False)
            tmp.write("\n")
            tmp.flush()
            os.fsync(tmp.fileno())
        except Exception:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise
    os.replace(tmp_path, path)


def prekeys_path(state):
    custom_path = getattr(state, "prekeys_path", None)
    if custom_path:
        return custom_path
    return str(PREKEYS_DIR / f"{state.username}_prekeys.json")


def load_local_prekeys(state):
    path = prekeys_path(state)
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("ficheiro local de prekeys inválido")
    return data


def save_local_prekeys(state, prekeys):
    _write_json_file(prekeys_path(state), prekeys)


def public_prekey_from_entry(prekey_id, entry):
    return {
        "type": SIGNED_PREKEY_TYPE,
        "version": SIGNED_PREKEY_VERSION,
        "prekey_id": prekey_id,
        "algorithm": SIGNED_PREKEY_ALGORITHM,
        "public_key": entry["public_key"],
        "signature": entry["signature"],
        "created_at": entry["created_at"],
    }


def generate_and_store_signed_prekeys(state, count=10):
    public_prekeys = []
    with _PREKEYS_LOCK:
        prekeys = load_local_prekeys(state)
        for _ in range(count):
            public_prekey, private_key = generate_signed_prekey(state.username, state.private_key)
            prekey_id = public_prekey["prekey_id"]
            prekeys[prekey_id] = {
                "private_key": private_key_to_pem(private_key),
                "public_key": public_prekey["public_key"],
                "signature": public_prekey["signature"],
                "created_at": public_prekey["created_at"],
                "used": False,
                "published": False,
            }
            public_prekeys.append(public_prekey)
        save_local_prekeys(state, prekeys)
    return public_prekeys


def mark_prekeys_published(state, prekey_ids):
    with _PREKEYS_LOCK:
        prekeys = load_local_prekeys(state)
        for prekey_id in prekey_ids:
            if prekey_id in prekeys:
                prekeys[prekey_id]["published"] = True
        save_local_prekeys(state, prekeys)


def publish_signed_prekeys(state, count=10):
    public_prekeys = generate_and_store_signed_prekeys(state, count)
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {
            "command": "publish_prekeys",
            "prekeys": public_prekeys,
        },
    )
    if resp is None:
        print("Ligação perdida ao publicar signed prekeys.")
        return False
    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao publicar signed prekeys"))
        return False

    accepted = resp.get("accepted_prekey_ids", [])
    if isinstance(accepted, list):
        mark_prekeys_published(state, [prekey_id for prekey_id in accepted if isinstance(prekey_id, str)])
    return True


def get_recipient_signed_prekey(state, target, identity_public_key):
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "get_prekey", "target": target},
    )
    if resp is None:
        print("Ligação perdida ao pedir signed prekey.")
        return None
    if resp.get("status") != "ok":
        print(resp.get("message", "signed prekey indisponível"))
        return None

    prekey = resp.get("prekey")
    if not verify_signed_prekey(target, identity_public_key, prekey):
        print(f"Signed prekey de {target} inválida.")
        return None
    return prekey


def load_private_prekey(state, prekey_id):
    with _PREKEYS_LOCK:
        prekeys = load_local_prekeys(state)
        entry = prekeys.get(prekey_id)
        if not isinstance(entry, dict):
            raise ValueError("private prekey local desconhecida")
        if entry.get("used") is True:
            raise ValueError("private prekey local já foi usada")
        private_key_pem = entry.get("private_key")
        if not isinstance(private_key_pem, str) or not private_key_pem:
            raise ValueError("private prekey local inválida")
        return x25519_private_key_from_pem(private_key_pem)


def mark_prekey_used(state, prekey_id):
    with _PREKEYS_LOCK:
        prekeys = load_local_prekeys(state)
        entry = prekeys.get(prekey_id)
        if not isinstance(entry, dict):
            raise ValueError("private prekey local desconhecida")
        entry["used"] = True
        entry["destroyed_at"] = utc_timestamp()
        entry.pop("private_key", None)
        prekeys[prekey_id] = entry
        save_local_prekeys(state, prekeys)
