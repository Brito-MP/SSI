from crypto_utils import public_key_from_pem, verify_protected_contacts, verify_protected_groups
from storage import PROTECTED_CONTACTS_FIELD, PROTECTED_GROUPS_FIELD, set_protected_contacts, set_protected_groups


def protected_contacts_for_user(user_data):
    return user_data.get(PROTECTED_CONTACTS_FIELD)


def protected_groups_for_user(user_data):
    return user_data.get(PROTECTED_GROUPS_FIELD)


def user_public_key(user_data):
    return public_key_from_pem(user_data["public_key"])


def verify_contacts_for_user(user_data, username, protected_contacts):
    return verify_protected_contacts(protected_contacts, username, user_public_key(user_data))


def verify_groups_for_user(user_data, username, protected_groups):
    return verify_protected_groups(protected_groups, username, user_public_key(user_data))


def store_protected_contacts(user_data, protected_contacts):
    set_protected_contacts(user_data, protected_contacts)


def store_protected_groups(user_data, protected_groups):
    set_protected_groups(user_data, protected_groups)
