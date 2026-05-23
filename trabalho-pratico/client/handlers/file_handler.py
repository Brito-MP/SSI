import json
import os
import sys
import tempfile
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from crypto_utils import (
    e2ee_public_key_binding_bytes,
    public_key_from_pem,
    public_key_to_pem,
    sign_message,
    utc_timestamp,
    verify_signature,
    x25519_public_key_from_pem,
)
from handlers.message_handler import build_message_envelope, process_incoming_message

BUNDLE_TYPE = "ssi_bundle"
BUNDLE_VERSION = 1
MESSAGE_FILE_TYPE = "ssi_message"
MESSAGE_FILE_VERSION = 1
MESSAGE_FILE_ALGORITHM = "ssi-e2ee-v2-aes-256-gcm-aad"


def _read_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError("ficheiro JSON inválido") from exc


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


def build_public_bundle(state):
    e2ee_public_key_pem = public_key_to_pem(state.x25519_public_key)
    return {
        "type": BUNDLE_TYPE,
        "version": BUNDLE_VERSION,
        "username": state.username,
        "public_keys": {
            "identity_key": public_key_to_pem(state.public_key),
            "e2ee_key": e2ee_public_key_pem,
            "e2ee_key_signature": sign_message(
                e2ee_public_key_binding_bytes(state.username, e2ee_public_key_pem),
                state.private_key,
            ),
        },
        "exported_at": utc_timestamp(),
    }


def validate_public_bundle(bundle):
    if not isinstance(bundle, dict):
        raise ValueError("bundle inválido")
    if bundle.get("type") != BUNDLE_TYPE or bundle.get("version") != BUNDLE_VERSION:
        raise ValueError("tipo ou versão de bundle inválidos")

    username = bundle.get("username")
    public_keys = bundle.get("public_keys")
    if not isinstance(username, str) or not username:
        raise ValueError("username em falta no bundle")
    if not isinstance(public_keys, dict):
        raise ValueError("public_keys em falta no bundle")

    identity_key_pem = public_keys.get("identity_key")
    e2ee_key_pem = public_keys.get("e2ee_key")
    e2ee_key_signature = public_keys.get("e2ee_key_signature")
    if not all(isinstance(value, str) and value for value in [identity_key_pem, e2ee_key_pem, e2ee_key_signature]):
        raise ValueError("chaves públicas em falta no bundle")

    identity_key = public_key_from_pem(identity_key_pem)
    e2ee_key = x25519_public_key_from_pem(e2ee_key_pem)
    if not verify_signature(e2ee_public_key_binding_bytes(username, e2ee_key_pem), e2ee_key_signature, identity_key):
        raise ValueError("assinatura da chave E2EE inválida")

    return username, identity_key, e2ee_key


def import_public_bundle(state, bundle):
    username, identity_key, e2ee_key = validate_public_bundle(bundle)
    if username == state.username:
        raise ValueError("não é necessário importar o próprio bundle")

    with state.key_cache_lock:
        existing_identity = state.key_cache.get(username)
        existing_e2ee = state.e2ee_key_cache.get(username)
        if existing_identity is not None and public_key_to_pem(existing_identity) != public_key_to_pem(identity_key):
            raise ValueError("bundle tenta substituir chave de identidade já conhecida")
        if existing_e2ee is not None and public_key_to_pem(existing_e2ee) != public_key_to_pem(e2ee_key):
            raise ValueError("bundle tenta substituir chave E2EE já conhecida")
        state.key_cache[username] = identity_key
        state.e2ee_key_cache[username] = e2ee_key
        state.contacts.add(username)

    return username


def build_message_file(envelope):
    return {
        "type": MESSAGE_FILE_TYPE,
        "version": MESSAGE_FILE_VERSION,
        "algorithm": MESSAGE_FILE_ALGORITHM,
        "envelope": envelope,
    }


def validate_message_file(data):
    if not isinstance(data, dict):
        raise ValueError("ficheiro de mensagem inválido")
    if data.get("type") != MESSAGE_FILE_TYPE or data.get("version") != MESSAGE_FILE_VERSION:
        raise ValueError("tipo ou versão de mensagem inválidos")
    if data.get("algorithm") != MESSAGE_FILE_ALGORITHM:
        raise ValueError("algoritmo de mensagem inválido")

    envelope = data.get("envelope")
    if not isinstance(envelope, dict):
        raise ValueError("envelope em falta")
    required = ["message_id", "from", "to", "timestamp", "payload", "signature"]
    if not all(field in envelope for field in required):
        raise ValueError("campos obrigatórios em falta no envelope")
    if not all(isinstance(envelope.get(field), str) and envelope.get(field) for field in ["message_id", "from", "to", "timestamp", "signature"]):
        raise ValueError("metadados inválidos no envelope")
    if not isinstance(envelope.get("payload"), dict):
        raise ValueError("payload inválido no envelope")
    return envelope


def cmd_export_bundle(state, path):
    try:
        _write_json_file(path, build_public_bundle(state))
    except Exception as exc:
        print(f"Erro ao exportar bundle: {exc}")
        return False
    print(f"Bundle público exportado para {path}.")
    return True


def cmd_import_bundle(state, path):
    try:
        bundle = _read_json_file(path)
        username = import_public_bundle(state, bundle)
    except Exception as exc:
        print(f"Erro ao importar bundle: {exc}")
        return False
    print(f"Bundle de {username} importado.")
    return True


def cmd_export_msg(state, target, text, path):
    with state.key_cache_lock:
        target_keys = None
        if target in state.key_cache and target in state.e2ee_key_cache:
            target_keys = {
                "identity_public_key": state.key_cache[target],
                "e2ee_public_key": state.e2ee_key_cache[target],
            }

    if target_keys is None:
        print(f"Sem bundle/chave importada para {target}.")
        return False

    try:
        envelope = build_message_envelope(state.username, target, text, state.private_key, target_keys)
        _write_json_file(path, build_message_file(envelope))
    except Exception as exc:
        print(f"Erro ao exportar mensagem: {exc}")
        return False
    print(f"Mensagem cifrada exportada para {path}.")
    return True


def cmd_import_msg(state, path):
    try:
        data = _read_json_file(path)
        envelope = validate_message_file(data)
        if envelope["to"] != state.username:
            print("Mensagem não é destinada a este utilizador.")
            return False
        before = state.has_seen_message(envelope["message_id"])
        process_incoming_message(envelope, state)
        if not before and state.has_seen_message(envelope["message_id"]):
            return True
    except Exception as exc:
        print(f"Erro ao importar mensagem: {exc}")
        return False
    print("Mensagem inválida ou adulterada.")
    return False
