import os
import json
import base64
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


E2EE_MESSAGE_VERSION = 2
GROUP_KEY_SHARE_TYPE = "group_key_share"
GROUP_MESSAGE_TYPE = "group_message"
DEFAULT_GROUP_KEY_VERSION = 1
SIGNED_PREKEY_TYPE = "signed_prekey"
SIGNED_PREKEY_VERSION = 1
SIGNED_PREKEY_ALGORITHM = "X25519"
OFFLINE_PREKEY_MESSAGE_TYPE = "offline_prekey_message"
OFFLINE_PREKEY_MESSAGE_VERSION = 1
OFFLINE_PREKEY_MESSAGE_ALGORITHM = "x25519-signed-prekey-hkdf-sha256-aes-256-gcm"
OFFLINE_PREKEY_HKDF_INFO = b"SSI offline signed prekey message v1"
SESSION_INIT_TYPE = "session_init"
SESSION_RESPONSE_TYPE = "session_response"
ONLINE_SESSION_MESSAGE_TYPE = "online_session_message"
ONLINE_SESSION_MESSAGE_VERSION = 1
ONLINE_SESSION_MESSAGE_ALGORITHM = "x25519-ephemeral-session-hkdf-sha256-aes-256-gcm"
ONLINE_SESSION_HKDF_INFO = b"SSI online ephemeral session v1"


def build_message_aad(message_id, sender, recipient, timestamp) -> bytes:
    aad_obj = {
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_offline_prekey_aad(message_id, sender, recipient, timestamp, prekey_id, ephemeral_public_key) -> bytes:
    aad_obj = {
        "type": OFFLINE_PREKEY_MESSAGE_TYPE,
        "version": OFFLINE_PREKEY_MESSAGE_VERSION,
        "algorithm": OFFLINE_PREKEY_MESSAGE_ALGORITHM,
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
        "prekey_id": prekey_id,
        "ephemeral_public_key": ephemeral_public_key,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_online_session_aad(session_id, message_id, sender, recipient, timestamp, counter) -> bytes:
    aad_obj = {
        "type": ONLINE_SESSION_MESSAGE_TYPE,
        "version": ONLINE_SESSION_MESSAGE_VERSION,
        "algorithm": ONLINE_SESSION_MESSAGE_ALGORITHM,
        "session_id": session_id,
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
        "counter": counter,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_group_aad(group_id, sender, recipient, message_id, timestamp) -> bytes:
    aad_obj = {
        "group_id": group_id,
        "message_id": message_id,
        "from": sender,
        "to": recipient,
        "timestamp": timestamp,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, path: str):
    pem = private_key_to_pem(private_key).encode()
    with open(path, "wb") as f:
        f.write(pem)


def private_key_to_pem(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()


def save_public_key(public_key, path: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def public_key_from_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def x25519_public_key_from_pem(pem: str):
    public_key = public_key_from_pem(pem)
    if not isinstance(public_key, x25519.X25519PublicKey):
        raise TypeError("chave pública E2EE não é X25519")
    return public_key


def x25519_private_key_from_pem(pem: str):
    private_key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise TypeError("chave privada E2EE não é X25519")
    return private_key


def _x25519_public_raw(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


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


def build_session_handshake_signing_data(msg: dict) -> bytes:
    return canonical_message_bytes({
        "type": msg["type"],
        "session_id": msg["session_id"],
        "from": msg["from"],
        "to": msg["to"],
        "ephemeral_public_key": msg["ephemeral_public_key"],
        "timestamp": msg["timestamp"],
    })


def verify_session_ephemeral_signature(msg: dict, identity_public_key) -> bool:
    required = ["type", "session_id", "from", "to", "ephemeral_public_key", "timestamp", "signature"]
    if not isinstance(msg, dict) or not all(isinstance(msg.get(field), str) and msg.get(field) for field in required):
        return False
    if msg.get("type") not in {SESSION_INIT_TYPE, SESSION_RESPONSE_TYPE}:
        return False
    try:
        x25519_public_key_from_pem(msg["ephemeral_public_key"])
        signing_data = build_session_handshake_signing_data(msg)
    except Exception:
        return False
    return verify_signature(signing_data, msg["signature"], identity_public_key)


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


def encrypt_for_recipient(plaintext: str, recipient_public_key, aad: bytes | None = None):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)

    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }


def encrypt_for_recipient_v2(plaintext: str, recipient_x25519_public_key, aad: bytes | None = None):
    if not isinstance(recipient_x25519_public_key, x25519.X25519PublicKey):
        raise TypeError("chave pública do destinatário não é X25519")

    sender_ephemeral_private_key, sender_ephemeral_public_key = generate_x25519_keypair()
    sender_ephemeral_raw = _x25519_public_raw(sender_ephemeral_public_key)
    recipient_static_raw = _x25519_public_raw(recipient_x25519_public_key)

    shared_secret = sender_ephemeral_private_key.exchange(recipient_x25519_public_key)
    aes_key = _derive_e2ee_v2_key(shared_secret, sender_ephemeral_raw, recipient_static_raw)

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), aad)

    return {
        "version": E2EE_MESSAGE_VERSION,
        "sender_ephemeral_key": base64.b64encode(sender_ephemeral_raw).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def encrypt_for_signed_prekey(
    plaintext: str,
    recipient_prekey: dict,
    sender: str,
    recipient: str,
    message_id: str,
    timestamp: str,
):
    prekey_id = recipient_prekey["prekey_id"]
    recipient_prekey_public_key = x25519_public_key_from_pem(recipient_prekey["public_key"])
    sender_ephemeral_private_key, sender_ephemeral_public_key = generate_x25519_keypair()
    sender_ephemeral_raw = _x25519_public_raw(sender_ephemeral_public_key)
    recipient_prekey_raw = _x25519_public_raw(recipient_prekey_public_key)

    shared_secret = sender_ephemeral_private_key.exchange(recipient_prekey_public_key)
    aes_key = _derive_offline_prekey_message_key(
        shared_secret,
        sender_ephemeral_raw,
        recipient_prekey_raw,
        prekey_id,
    )

    ephemeral_public_key_pem = public_key_to_pem(sender_ephemeral_public_key)
    aad = build_offline_prekey_aad(
        message_id,
        sender,
        recipient,
        timestamp,
        prekey_id,
        ephemeral_public_key_pem,
    )
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext.encode(), aad)

    return {
        "prekey_id": prekey_id,
        "ephemeral_public_key": ephemeral_public_key_pem,
        "payload": {
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
        },
    }


def decrypt_from_sender_v1(payload: dict, recipient_private_key, aad: bytes | None = None) -> str:
    encrypted_key = base64.b64decode(payload["encrypted_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    aes_key = recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode()


def decrypt_from_sender_v2(payload: dict, recipient_x25519_private_key, aad: bytes | None = None) -> str:
    if not isinstance(recipient_x25519_private_key, x25519.X25519PrivateKey):
        raise TypeError("chave privada E2EE não é X25519")

    sender_ephemeral_raw = base64.b64decode(payload["sender_ephemeral_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    sender_ephemeral_public_key = x25519.X25519PublicKey.from_public_bytes(sender_ephemeral_raw)
    recipient_static_raw = _x25519_public_raw(recipient_x25519_private_key.public_key())
    shared_secret = recipient_x25519_private_key.exchange(sender_ephemeral_public_key)
    aes_key = _derive_e2ee_v2_key(shared_secret, sender_ephemeral_raw, recipient_static_raw)

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode()


def decrypt_from_sender(payload: dict, recipient_private_key, recipient_x25519_private_key=None, aad: bytes | None = None) -> str:
    if payload.get("version") == E2EE_MESSAGE_VERSION:
        return decrypt_from_sender_v2(payload, recipient_x25519_private_key, aad)
    return decrypt_from_sender_v1(payload, recipient_private_key, aad)


def decrypt_from_signed_prekey(
    payload: dict,
    recipient_prekey_private_key,
    ephemeral_public_key_pem: str,
    prekey_id: str,
    sender: str,
    recipient: str,
    message_id: str,
    timestamp: str,
) -> str:
    if isinstance(recipient_prekey_private_key, str):
        recipient_prekey_private_key = x25519_private_key_from_pem(recipient_prekey_private_key)
    if not isinstance(recipient_prekey_private_key, x25519.X25519PrivateKey):
        raise TypeError("chave privada de prekey não é X25519")

    sender_ephemeral_public_key = x25519_public_key_from_pem(ephemeral_public_key_pem)
    sender_ephemeral_raw = _x25519_public_raw(sender_ephemeral_public_key)
    recipient_prekey_raw = _x25519_public_raw(recipient_prekey_private_key.public_key())
    shared_secret = recipient_prekey_private_key.exchange(sender_ephemeral_public_key)
    aes_key = _derive_offline_prekey_message_key(
        shared_secret,
        sender_ephemeral_raw,
        recipient_prekey_raw,
        prekey_id,
    )

    aad = build_offline_prekey_aad(
        message_id,
        sender,
        recipient,
        timestamp,
        prekey_id,
        ephemeral_public_key_pem,
    )
    nonce = base64.b64decode(payload["nonce"].encode(), validate=True)
    ciphertext = base64.b64decode(payload["ciphertext"].encode(), validate=True)
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, aad)
    return plaintext.decode()


def encrypt_online_session_message(session_key: bytes, plaintext: str, aad: bytes | None = None):
    if not isinstance(session_key, bytes) or len(session_key) != 32:
        raise ValueError("session_key inválida")
    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext.encode(), aad)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_online_session_message(session_key: bytes, payload: dict, aad: bytes | None = None):
    if not isinstance(session_key, bytes) or len(session_key) != 32:
        raise ValueError("session_key inválida")
    nonce = base64.b64decode(payload["nonce"].encode(), validate=True)
    ciphertext = base64.b64decode(payload["ciphertext"].encode(), validate=True)
    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, aad)
    return plaintext.decode()


def generate_group_key() -> str:
    key = AESGCM.generate_key(bit_length=256)
    return base64.b64encode(key).decode()


def decode_group_key(group_key: str) -> bytes:
    if not isinstance(group_key, str) or not group_key:
        raise ValueError("group_key inválida")

    try:
        key = base64.b64decode(group_key.encode(), validate=True)
    except Exception as exc:
        raise ValueError("group_key inválida") from exc

    if len(key) != 32:
        raise ValueError("group_key deve ter 256 bits")
    return key


def is_valid_group_key(group_key: str) -> bool:
    try:
        decode_group_key(group_key)
    except Exception:
        return False
    return True


def encrypt_group_payload(group_key: str, payload: dict, aad: bytes | None = None):
    key = decode_group_key(group_key)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_group_payload(group_key: str, nonce_b64: str, ciphertext_b64: str, aad: bytes | None = None):
    key = decode_group_key(group_key)
    nonce = base64.b64decode(nonce_b64.encode(), validate=True)
    ciphertext = base64.b64decode(ciphertext_b64.encode(), validate=True)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    payload = json.loads(plaintext.decode())
    if not isinstance(payload, dict):
        raise ValueError("payload de grupo inválido")
    return payload


def group_message_signed_part(msg: dict):
    signed_part = {
        "type": GROUP_MESSAGE_TYPE,
        "group_id": msg["group_id"],
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
    }
    return signed_part


def offline_prekey_message_signed_part(msg: dict):
    return {
        "type": OFFLINE_PREKEY_MESSAGE_TYPE,
        "version": msg["version"],
        "algorithm": msg["algorithm"],
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "prekey_id": msg["prekey_id"],
        "ephemeral_public_key": msg["ephemeral_public_key"],
        "payload": msg["payload"],
    }


def online_session_message_signed_part(msg: dict):
    return {
        "type": ONLINE_SESSION_MESSAGE_TYPE,
        "version": msg["version"],
        "algorithm": msg["algorithm"],
        "session_id": msg["session_id"],
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "counter": msg["counter"],
        "payload": msg["payload"],
    }


def sign_message(data: bytes, private_key) -> str:
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def canonical_message_bytes(message_dict: dict) -> bytes:
    return json.dumps(message_dict, sort_keys=True, separators=(",", ":")).encode()


def e2ee_public_key_binding_bytes(username: str, e2ee_public_key_pem: str) -> bytes:
    return canonical_message_bytes({
        "type": "e2ee_public_key",
        "version": 1,
        "username": username,
        "e2ee_public_key": e2ee_public_key_pem,
    })


def normalize_contact_list(contacts):
    clean_contacts = set()
    if not isinstance(contacts, (list, set, tuple)):
        return []

    for contact in contacts:
        if isinstance(contact, str):
            clean_contact = contact.strip()
            if clean_contact:
                clean_contacts.add(clean_contact)

    return sorted(clean_contacts)


def normalize_groups(groups):
    clean_groups = {}
    if not isinstance(groups, dict):
        return {}

    for group_id, group in groups.items():
        if not isinstance(group_id, str):
            continue
        clean_group_id = group_id.strip()
        if not clean_group_id or not isinstance(group, dict):
            continue

        name = group.get("name", clean_group_id)
        if not isinstance(name, str):
            name = clean_group_id
        clean_name = name.strip() or clean_group_id

        clean_members = normalize_contact_list(group.get("members", []))
        clean_group = {
            "name": clean_name,
            "members": clean_members,
            "group_key_version": normalize_group_key_version(group.get("group_key_version")),
        }
        group_key = group.get("group_key")
        if is_valid_group_key(group_key):
            clean_group["group_key"] = group_key
        rotation_leader = group.get("group_key_rotation_leader")
        if group.get("group_key_rotation_pending") is True and isinstance(rotation_leader, str) and rotation_leader.strip():
            clean_group["group_key_rotation_pending"] = True
            clean_group["group_key_rotation_leader"] = rotation_leader.strip()

        clean_groups[clean_group_id] = clean_group

    return dict(sorted(clean_groups.items()))


def normalize_group_key_version(version) -> int:
    if isinstance(version, bool):
        return DEFAULT_GROUP_KEY_VERSION
    if isinstance(version, int) and version >= DEFAULT_GROUP_KEY_VERSION:
        return version
    return DEFAULT_GROUP_KEY_VERSION


def protected_contacts_signed_part(owner: str, payload: dict):
    return {
        "type": "contacts",
        "version": 1,
        "owner": owner,
        "payload": payload,
    }


def protect_contacts(owner: str, contacts, private_key, public_key):
    contact_data = {
        "owner": owner,
        "contacts": normalize_contact_list(contacts),
    }
    payload = encrypt_for_recipient(json.dumps(contact_data, separators=(",", ":")), public_key)
    signed_part = protected_contacts_signed_part(owner, payload)
    signature = sign_message(canonical_message_bytes(signed_part), private_key)
    return {
        **signed_part,
        "signature": signature,
    }


def verify_protected_contacts(protected_contacts: dict, owner: str, public_key) -> bool:
    if not isinstance(protected_contacts, dict):
        return False

    payload = protected_contacts.get("payload")
    if not isinstance(payload, dict):
        return False

    if protected_contacts.get("type") != "contacts":
        return False
    if protected_contacts.get("version") != 1:
        return False
    if protected_contacts.get("owner") != owner:
        return False
    if not all(isinstance(payload.get(field), str) for field in ["nonce", "ciphertext", "encrypted_key"]):
        return False
    if not isinstance(protected_contacts.get("signature"), str):
        return False

    signed_part = protected_contacts_signed_part(owner, payload)
    return verify_signature(canonical_message_bytes(signed_part), protected_contacts["signature"], public_key)


def unprotect_contacts(protected_contacts: dict, owner: str, private_key, public_key):
    if not verify_protected_contacts(protected_contacts, owner, public_key):
        raise ValueError("assinatura dos contactos inválida")

    plaintext = decrypt_from_sender(protected_contacts["payload"], private_key)
    contact_data = json.loads(plaintext)
    if not isinstance(contact_data, dict) or contact_data.get("owner") != owner:
        raise ValueError("dono dos contactos inválido")

    return normalize_contact_list(contact_data.get("contacts", []))


def protected_groups_signed_part(owner: str, payload: dict):
    return {
        "type": "groups",
        "version": 1,
        "owner": owner,
        "payload": payload,
    }


def protect_groups(owner: str, groups, private_key, public_key):
    group_data = {
        "owner": owner,
        "groups": normalize_groups(groups),
    }
    payload = encrypt_for_recipient(json.dumps(group_data, separators=(",", ":")), public_key)
    signed_part = protected_groups_signed_part(owner, payload)
    signature = sign_message(canonical_message_bytes(signed_part), private_key)
    return {
        **signed_part,
        "signature": signature,
    }


def verify_protected_groups(protected_groups: dict, owner: str, public_key) -> bool:
    if not isinstance(protected_groups, dict):
        return False

    payload = protected_groups.get("payload")
    if not isinstance(payload, dict):
        return False

    if protected_groups.get("type") != "groups":
        return False
    if protected_groups.get("version") != 1:
        return False
    if protected_groups.get("owner") != owner:
        return False
    if not all(isinstance(payload.get(field), str) for field in ["nonce", "ciphertext", "encrypted_key"]):
        return False
    if not isinstance(protected_groups.get("signature"), str):
        return False

    signed_part = protected_groups_signed_part(owner, payload)
    return verify_signature(canonical_message_bytes(signed_part), protected_groups["signature"], public_key)


def unprotect_groups(protected_groups: dict, owner: str, private_key, public_key):
    if not verify_protected_groups(protected_groups, owner, public_key):
        raise ValueError("assinatura dos grupos inválida")

    plaintext = decrypt_from_sender(protected_groups["payload"], private_key)
    group_data = json.loads(plaintext)
    if not isinstance(group_data, dict) or group_data.get("owner") != owner:
        raise ValueError("dono dos grupos inválido")

    return normalize_groups(group_data.get("groups", {}))


def generate_message_id() -> str:
    return str(uuid.uuid4())


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
