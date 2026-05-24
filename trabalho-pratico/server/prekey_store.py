from crypto_utils import (
    SIGNED_PREKEY_ALGORITHM,
    SIGNED_PREKEY_TYPE,
    SIGNED_PREKEY_VERSION,
    public_key_from_pem,
    verify_signed_prekey,
    x25519_public_key_from_pem,
)
from server.server_common import MAX_SIGNED_PREKEYS_PER_USER, SIGNED_PREKEYS_FIELD


def clean_public_signed_prekey(prekey: dict):
    if not isinstance(prekey, dict):
        raise ValueError("signed prekey inválida")
    clean = {
        "type": prekey.get("type", SIGNED_PREKEY_TYPE),
        "version": prekey.get("version", SIGNED_PREKEY_VERSION),
        "prekey_id": prekey.get("prekey_id"),
        "algorithm": prekey.get("algorithm"),
        "public_key": prekey.get("public_key"),
        "signature": prekey.get("signature"),
        "created_at": prekey.get("created_at"),
    }
    required = ["prekey_id", "algorithm", "public_key", "signature", "created_at"]
    if not all(isinstance(clean.get(field), str) and clean.get(field) for field in required):
        raise ValueError("campos obrigatórios da signed prekey em falta")
    if clean["type"] != SIGNED_PREKEY_TYPE or clean["version"] != SIGNED_PREKEY_VERSION:
        raise ValueError("tipo ou versão de signed prekey inválidos")
    if clean["algorithm"] != SIGNED_PREKEY_ALGORITHM:
        raise ValueError("algoritmo de signed prekey inválido")
    x25519_public_key_from_pem(clean["public_key"])
    return clean

def publish_signed_prekeys_for_user(user_data: dict, username: str, prekeys):
    if not isinstance(prekeys, list):
        raise ValueError("lista de signed prekeys inválida")

    identity_public_key = public_key_from_pem(user_data["public_key"])
    stored = user_data.get(SIGNED_PREKEYS_FIELD)
    if not isinstance(stored, dict):
        stored = {}

    accepted = []
    for prekey in prekeys:
        clean = clean_public_signed_prekey(prekey)
        prekey_id = clean["prekey_id"]
        if prekey_id in stored:
            continue
        if not verify_signed_prekey(username, identity_public_key, clean):
            raise ValueError("assinatura da signed prekey inválida")
        if len(stored) >= MAX_SIGNED_PREKEYS_PER_USER:
            break
        stored[prekey_id] = {
            **clean,
            "state": "available",
        }
        accepted.append(prekey_id)

    user_data[SIGNED_PREKEYS_FIELD] = stored
    return accepted

def pop_available_signed_prekey(user_data: dict):
    stored = user_data.get(SIGNED_PREKEYS_FIELD)
    if not isinstance(stored, dict):
        return None

    for prekey_id, prekey in sorted(stored.items(), key=lambda item: item[1].get("created_at", "")):
        if not isinstance(prekey, dict) or prekey.get("state") != "available":
            continue
        clean = clean_public_signed_prekey(prekey)
        stored[prekey_id] = {
            **prekey,
            "state": "used",
        }
        user_data[SIGNED_PREKEYS_FIELD] = stored
        return clean

    return None
