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


# Guarda a chave privada no disco local do cliente.
# O servidor nunca deve ter acesso a este ficheiro.
def save_private_key(private_key, path: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, "wb") as f:
        f.write(pem)


# Guarda a chave pública para que o utilizador a possa publicar no servidor.
def save_public_key(public_key, path: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(pem)


# Lê a chave privada local do utilizador.
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# Lê uma chave pública guardada em PEM.
def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# Converte a chave pública para texto PEM para a enviar pelo protocolo.
def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


# Reconstrói uma chave pública a partir de texto PEM.
def public_key_from_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode())


def x25519_public_key_from_pem(pem: str):
    public_key = public_key_from_pem(pem)
    if not isinstance(public_key, x25519.X25519PublicKey):
        raise TypeError("chave pública E2EE não é X25519")
    return public_key


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


# Cifra uma mensagem para um destinatário específico.
# Gera uma chave AES aleatória para esta mensagem, cifra o texto com AES-GCM
# e encapsula a chave AES com a chave pública RSA do destinatário.
def encrypt_for_recipient(plaintext: str, recipient_public_key):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

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


def encrypt_for_recipient_v2(plaintext: str, recipient_x25519_public_key):
    if not isinstance(recipient_x25519_public_key, x25519.X25519PublicKey):
        raise TypeError("chave pública do destinatário não é X25519")

    sender_ephemeral_private_key, sender_ephemeral_public_key = generate_x25519_keypair()
    sender_ephemeral_raw = _x25519_public_raw(sender_ephemeral_public_key)
    recipient_static_raw = _x25519_public_raw(recipient_x25519_public_key)

    shared_secret = sender_ephemeral_private_key.exchange(recipient_x25519_public_key)
    aes_key = _derive_e2ee_v2_key(shared_secret, sender_ephemeral_raw, recipient_static_raw)

    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    return {
        "version": E2EE_MESSAGE_VERSION,
        "sender_ephemeral_key": base64.b64encode(sender_ephemeral_raw).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


# Decifra uma mensagem recebida por este utilizador.
def decrypt_from_sender_v1(payload: dict, recipient_private_key) -> str:
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
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


def decrypt_from_sender_v2(payload: dict, recipient_x25519_private_key) -> str:
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
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


# Decifra uma mensagem recebida por este utilizador.
def decrypt_from_sender(payload: dict, recipient_private_key, recipient_x25519_private_key=None) -> str:
    if payload.get("version") == E2EE_MESSAGE_VERSION:
        return decrypt_from_sender_v2(payload, recipient_x25519_private_key)
    return decrypt_from_sender_v1(payload, recipient_private_key)


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


def encrypt_group_payload(group_key: str, payload: dict):
    key = decode_group_key(group_key)
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(",", ":")).encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_group_payload(group_key: str, nonce_b64: str, ciphertext_b64: str):
    key = decode_group_key(group_key)
    nonce = base64.b64decode(nonce_b64.encode(), validate=True)
    ciphertext = base64.b64decode(ciphertext_b64.encode(), validate=True)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    payload = json.loads(plaintext.decode())
    if not isinstance(payload, dict):
        raise ValueError("payload de grupo inválido")
    return payload


def group_message_signed_part(msg: dict):
    return {
        "type": GROUP_MESSAGE_TYPE,
        "group_id": msg["group_id"],
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "nonce": msg["nonce"],
        "ciphertext": msg["ciphertext"],
    }


# Assina dados com a chave privada do remetente.
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


# Verifica a assinatura de um remetente.
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


# Serializa um dicionário sempre da mesma maneira antes de assinar/verificar.
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
        }
        group_key = group.get("group_key")
        if is_valid_group_key(group_key):
            clean_group["group_key"] = group_key

        clean_groups[clean_group_id] = clean_group

    return dict(sorted(clean_groups.items()))


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


# Gera um identificador único para cada mensagem.
def generate_message_id() -> str:
    return str(uuid.uuid4())


# Cria um timestamp UTC em formato ISO 8601.
def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
