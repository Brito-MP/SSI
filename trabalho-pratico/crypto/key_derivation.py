from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.constants import OFFLINE_PREKEY_HKDF_INFO, ONLINE_SESSION_HKDF_INFO
from crypto.signatures import canonical_message_bytes

def _derive_e2ee_v2_key(shared_secret: bytes, sender_ephemeral_key: bytes, recipient_static_key: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ssi-chat-e2ee-v2" + sender_ephemeral_key + recipient_static_key,
    )
    return hkdf.derive(shared_secret)

def _derive_offline_prekey_message_key(
    shared_secret: bytes,
    sender_ephemeral_key: bytes,
    recipient_prekey: bytes,
    prekey_id: str,
) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=OFFLINE_PREKEY_HKDF_INFO + sender_ephemeral_key + recipient_prekey + prekey_id.encode("utf-8"),
    )
    return hkdf.derive(shared_secret)

def derive_online_session_key(
    shared_secret: bytes,
    session_id: str,
    initiator: str,
    responder: str,
    initiator_ephemeral_public_key: str,
    responder_ephemeral_public_key: str,
) -> bytes:
    context = canonical_message_bytes({
        "type": "online_session_context",
        "version": 1,
        "session_id": session_id,
        "initiator": initiator,
        "responder": responder,
        "initiator_ephemeral_public_key": initiator_ephemeral_public_key,
        "responder_ephemeral_public_key": responder_ephemeral_public_key,
    })
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=ONLINE_SESSION_HKDF_INFO + context,
    )
    return hkdf.derive(shared_secret)
