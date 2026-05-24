import uuid

from crypto.constants import SIGNED_PREKEY_ALGORITHM, SIGNED_PREKEY_TYPE, SIGNED_PREKEY_VERSION
from crypto.serialization import generate_x25519_keypair, public_key_to_pem, x25519_public_key_from_pem
from crypto.signatures import canonical_message_bytes, sign_message, verify_signature
from crypto.utils import utc_timestamp

def build_prekey_signing_data(username: str, prekey: dict) -> bytes:
    return canonical_message_bytes({
        "type": SIGNED_PREKEY_TYPE,
        "version": SIGNED_PREKEY_VERSION,
        "username": username,
        "prekey_id": prekey["prekey_id"],
        "algorithm": prekey["algorithm"],
        "public_key": prekey["public_key"],
        "created_at": prekey["created_at"],
    })

def sign_prekey(username: str, identity_private_key, prekey: dict) -> str:
    return sign_message(build_prekey_signing_data(username, prekey), identity_private_key)

def generate_signed_prekey(username: str, identity_private_key, prekey_id: str | None = None, created_at: str | None = None):
    private_key, public_key = generate_x25519_keypair()
    public_prekey = {
        "type": SIGNED_PREKEY_TYPE,
        "version": SIGNED_PREKEY_VERSION,
        "prekey_id": prekey_id or str(uuid.uuid4()),
        "algorithm": SIGNED_PREKEY_ALGORITHM,
        "public_key": public_key_to_pem(public_key),
        "created_at": created_at or utc_timestamp(),
    }
    public_prekey["signature"] = sign_prekey(username, identity_private_key, public_prekey)
    return public_prekey, private_key

def verify_signed_prekey(username: str, identity_public_key, prekey: dict) -> bool:
    if not isinstance(prekey, dict):
        return False
    required = ["prekey_id", "algorithm", "public_key", "signature", "created_at"]
    if not all(isinstance(prekey.get(field), str) and prekey.get(field) for field in required):
        return False
    if prekey.get("type", SIGNED_PREKEY_TYPE) != SIGNED_PREKEY_TYPE:
        return False
    if prekey.get("version", SIGNED_PREKEY_VERSION) != SIGNED_PREKEY_VERSION:
        return False
    if prekey.get("algorithm") != SIGNED_PREKEY_ALGORITHM:
        return False
    try:
        x25519_public_key_from_pem(prekey["public_key"])
        signing_data = build_prekey_signing_data(username, prekey)
    except Exception:
        return False
    return verify_signature(signing_data, prekey["signature"], identity_public_key)
