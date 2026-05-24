import json

from crypto.constants import DEFAULT_GROUP_KEY_VERSION
from crypto.e2ee import decrypt_from_sender, encrypt_for_recipient
from crypto.groups import is_valid_group_key
from crypto.signatures import canonical_message_bytes, sign_message, verify_signature

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
