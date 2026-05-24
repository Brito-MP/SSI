from crypto_utils import public_key_from_pem, public_key_to_pem, x25519_public_key_from_pem


def sender_public_key(users: dict, sender: str):
    return users.get(sender, {}).get("public_key")

def sender_certificate(users: dict, sender: str):
    return users.get(sender, {}).get("certificate")

def registered_user(users: dict, username: str):
    user_data = users.get(username)
    if not isinstance(user_data, dict) or "public_key" not in user_data or "certificate" not in user_data:
        return None
    return user_data

def canonical_public_key_pem(public_key_pem: str):
    return public_key_to_pem(public_key_from_pem(public_key_pem))

def canonical_e2ee_public_key_pem(public_key_pem: str):
    return public_key_to_pem(x25519_public_key_from_pem(public_key_pem))

def can_set_e2ee_public_key(existing_public_key: str | None, requested_public_key: str):
    requested_public_key = canonical_e2ee_public_key_pem(requested_public_key)
    if existing_public_key is None:
        return requested_public_key

    existing_public_key = canonical_e2ee_public_key_pem(existing_public_key)
    if existing_public_key != requested_public_key:
        raise ValueError("utilizador já registado com outra chave pública E2EE")

    return requested_public_key
