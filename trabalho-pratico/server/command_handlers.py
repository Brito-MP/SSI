from crypto_utils import e2ee_public_key_binding_bytes, public_key_from_pem, verify_signature
from protocol import send_json
from server.contact_group_store import (
    protected_contacts_for_user,
    protected_groups_for_user,
    store_protected_contacts,
    store_protected_groups,
    verify_contacts_for_user,
    verify_groups_for_user,
    user_public_key,
)
from server.message_store import ack_pending_messages, deliver_or_store_message, enrich_with_sender_keys, get_pending_messages
from server.prekey_store import pop_available_signed_prekey, publish_signed_prekeys_for_user
from server.server_common import E2EE_PUBLIC_KEY_FIELD, E2EE_PUBLIC_KEY_SIGNATURE_FIELD, ONLINE_ONLY_MESSAGE_TYPES, SIGNED_PREKEYS_FIELD
from server.server_state import is_user_online, set_online_user
from server.user_store import can_set_e2ee_public_key, canonical_public_key_pem, registered_user
from server.validators import is_valid_envelope
from storage import (
    PROTECTED_CONTACTS_FIELD,
    PROTECTED_GROUPS_FIELD,
    load_users,
    save_users,
    users_lock,
)


def handle_register(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    with users_lock():
        users = load_users()
        requested_username = msg.get("username")
        if requested_username != authenticated_username:
            send_json(conn, {
                "status": "error",
                "message": "username não corresponde ao certificado autenticado",
            })
            return None

        username = requested_username
        try:
            requested_public_key = canonical_public_key_pem(msg["public_key"])
        except Exception:
            send_json(conn, {"status": "error", "message": "chave pública inválida"})
            return None

        if requested_public_key != authenticated_public_key:
            send_json(conn, {
                "status": "error",
                "message": "chave pública não corresponde ao certificado autenticado",
            })
            return None

        try:
            requested_e2ee_public_key = can_set_e2ee_public_key(
                None,
                msg[E2EE_PUBLIC_KEY_FIELD],
            )
        except KeyError:
            send_json(conn, {"status": "error", "message": "chave pública E2EE em falta"})
            return None
        except Exception:
            send_json(conn, {"status": "error", "message": "chave pública E2EE inválida"})
            return None

        requested_e2ee_public_key_signature = msg.get(E2EE_PUBLIC_KEY_SIGNATURE_FIELD)
        if not isinstance(requested_e2ee_public_key_signature, str):
            send_json(conn, {"status": "error", "message": "assinatura da chave pública E2EE em falta"})
            return None

        if not verify_signature(
            e2ee_public_key_binding_bytes(username, requested_e2ee_public_key),
            requested_e2ee_public_key_signature,
            public_key_from_pem(requested_public_key),
        ):
            send_json(conn, {"status": "error", "message": "assinatura da chave pública E2EE inválida"})
            return None

        user_data = users.get(username, {})
        if not isinstance(user_data, dict):
            user_data = {}

        existing_public_key = user_data.get("public_key")
        if existing_public_key is not None:
            try:
                existing_public_key = canonical_public_key_pem(existing_public_key)
            except Exception:
                send_json(conn, {"status": "error", "message": "chave pública registada inválida"})
                return None

            if existing_public_key != requested_public_key:
                send_json(conn, {
                    "status": "error",
                    "message": "utilizador já registado com outra chave pública",
                })
                return None

        existing_e2ee_public_key = user_data.get(E2EE_PUBLIC_KEY_FIELD)
        try:
            requested_e2ee_public_key = can_set_e2ee_public_key(
                existing_e2ee_public_key,
                requested_e2ee_public_key,
            )
        except ValueError as exc:
            send_json(conn, {"status": "error", "message": str(exc)})
            return None
        except Exception:
            send_json(conn, {"status": "error", "message": "chave pública E2EE registada inválida"})
            return None

        user_data["public_key"] = requested_public_key
        user_data[E2EE_PUBLIC_KEY_FIELD] = requested_e2ee_public_key
        user_data[E2EE_PUBLIC_KEY_SIGNATURE_FIELD] = requested_e2ee_public_key_signature
        user_data["certificate"] = authenticated_certificate
        user_data.pop("contacts", None)
        user_data.pop("groups", None)
        users[username] = user_data
        save_users(users)
    set_online_user(username, conn)
    send_json(conn, {"status": "ok", "message": f"user '{username}' registado"})
    return username


def handle_get_user_key(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    users = load_users()
    target = msg["target"]
    if registered_user(users, target) is None:
        send_json(conn, {"status": "error", "message": "utilizador não existe"})
    else:
        send_json(conn, {
            "status": "ok",
            "target": target,
            "public_key": users[target]["public_key"],
            E2EE_PUBLIC_KEY_FIELD: users[target].get(E2EE_PUBLIC_KEY_FIELD),
            E2EE_PUBLIC_KEY_SIGNATURE_FIELD: users[target].get(E2EE_PUBLIC_KEY_SIGNATURE_FIELD),
            "certificate": users[target].get("certificate"),
            "online": is_user_online(target),
        })


def handle_publish_prekeys(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    with users_lock():
        users = load_users()
        user_data = registered_user(users, authenticated_username)
        if user_data is None:
            send_json(conn, {"status": "error", "message": "utilizador não registado"})
            return None

        try:
            accepted = publish_signed_prekeys_for_user(
                user_data,
                authenticated_username,
                msg.get("prekeys"),
            )
        except Exception as exc:
            send_json(conn, {"status": "error", "message": str(exc)})
            return None

        users[authenticated_username] = user_data
        save_users(users)

    send_json(conn, {
        "status": "ok",
        "accepted_prekey_ids": accepted,
        "available_prekeys": sum(
            1
            for prekey in user_data.get(SIGNED_PREKEYS_FIELD, {}).values()
            if isinstance(prekey, dict) and prekey.get("state") == "available"
        ),
    })


def handle_get_prekey(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    target = msg.get("target")
    with users_lock():
        users = load_users()
        user_data = registered_user(users, target)
        if user_data is None:
            send_json(conn, {"status": "error", "message": "utilizador não existe"})
            return None

        try:
            prekey = pop_available_signed_prekey(user_data)
        except Exception as exc:
            send_json(conn, {"status": "error", "message": str(exc)})
            return None

        if prekey is None:
            send_json(conn, {"status": "error", "message": "sem signed prekeys disponíveis"})
            return None

        users[target] = user_data
        save_users(users)

    send_json(conn, {
        "status": "ok",
        "target": target,
        "prekey": prekey,
    })


def handle_send_message(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    users = load_users()

    if not is_valid_envelope(msg):
        send_json(conn, {"status": "error", "message": "envelope de mensagem inválido"})
        return None

    if registered_user(users, msg["to"]) is None:
        send_json(conn, {"status": "error", "message": "destinatário não existe"})
        return None

    if msg["from"] != authenticated_username:
        send_json(conn, {"status": "error", "message": "remetente inconsistente com a sessão"})
        return None

    envelope, delivered_online, stored_encrypted = deliver_or_store_message(msg, users)
    if msg.get("type") in ONLINE_ONLY_MESSAGE_TYPES and not delivered_online:
        send_json(conn, {"status": "error", "message": "destinatário offline para sessão online"})
        return None

    send_json(conn, {
        "status": "ok",
        "message": "mensagem enviada",
        "message_id": envelope["message_id"],
        "stored_encrypted": stored_encrypted,
        "delivered_online": delivered_online,
    })


def handle_relay_session_envelope(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    users = load_users()

    if msg.get("type") not in {"session_response"}:
        return None

    if not is_valid_envelope(msg):
        return None

    if registered_user(users, msg["to"]) is None:
        return None

    if msg["from"] != authenticated_username:
        return None

    deliver_or_store_message(msg, users)


def handle_fetch_messages(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    requested_username = msg.get("username")

    if requested_username is None:
        send_json(conn, {"status": "error", "message": "username em falta"})
        return None

    if requested_username != authenticated_username:
        send_json(conn, {"status": "error", "message": "username inválido para esta sessão"})
        return None

    pending = get_pending_messages(requested_username)
    users = load_users()
    pending = enrich_with_sender_keys(pending, users)

    send_json(conn, {
        "status": "ok",
        "messages": pending
    })


def handle_ack_messages(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    requested_username = msg.get("username")
    if requested_username is None:
        send_json(conn, {"status": "error", "message": "username em falta"})
        return None

    if requested_username != authenticated_username:
        send_json(conn, {"status": "error", "message": "username inválido para esta sessão"})
        return None

    message_ids = msg.get("message_ids")
    if not isinstance(message_ids, list) or not all(isinstance(message_id, str) for message_id in message_ids):
        send_json(conn, {"status": "error", "message": "message_ids inválidos"})
        return None

    removed_count = ack_pending_messages(requested_username, message_ids)
    send_json(conn, {
        "status": "ok",
        "removed_count": removed_count,
    })


def handle_list_contacts(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    users = load_users()
    user_data = registered_user(users, authenticated_username)
    if user_data is None:
        send_json(conn, {"status": "error", "message": "utilizador não registado"})
        return None

    send_json(conn, {
        "status": "ok",
        "protected_contacts": protected_contacts_for_user(user_data),
    })


def handle_update_contacts(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    with users_lock():
        users = load_users()
        user_data = registered_user(users, authenticated_username)
        if user_data is None:
            send_json(conn, {"status": "error", "message": "utilizador não registado"})
            return None

        protected_contacts = msg.get("protected_contacts")
        try:
            user_public_key(user_data)
        except Exception:
            send_json(conn, {"status": "error", "message": "chave pública do utilizador inválida"})
            return None

        if not verify_contacts_for_user(user_data, authenticated_username, protected_contacts):
            send_json(conn, {"status": "error", "message": "contactos protegidos inválidos"})
            return None

        store_protected_contacts(user_data, protected_contacts)
        users[authenticated_username] = user_data
        save_users(users)

    send_json(conn, {
        "status": "ok",
        "message": "contactos atualizados",
        "protected_contacts": user_data[PROTECTED_CONTACTS_FIELD],
    })


def handle_list_groups(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    users = load_users()
    user_data = registered_user(users, authenticated_username)
    if user_data is None:
        send_json(conn, {"status": "error", "message": "utilizador não registado"})
        return None

    send_json(conn, {
        "status": "ok",
        "protected_groups": protected_groups_for_user(user_data),
    })


def handle_update_groups(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    with users_lock():
        users = load_users()
        user_data = registered_user(users, authenticated_username)
        if user_data is None:
            send_json(conn, {"status": "error", "message": "utilizador não registado"})
            return None

        protected_groups = msg.get("protected_groups")
        try:
            user_public_key(user_data)
        except Exception:
            send_json(conn, {"status": "error", "message": "chave pública do utilizador inválida"})
            return None

        if not verify_groups_for_user(user_data, authenticated_username, protected_groups):
            send_json(conn, {"status": "error", "message": "grupos protegidos inválidos"})
            return None

        store_protected_groups(user_data, protected_groups)
        users[authenticated_username] = user_data
        save_users(users)

    send_json(conn, {
        "status": "ok",
        "message": "grupos atualizados",
        "protected_groups": user_data[PROTECTED_GROUPS_FIELD],
    })


def handle_list_users(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    users = load_users()
    registered_users = [user for user in users if registered_user(users, user) is not None]
    send_json(conn, {
        "status": "ok",
        "users": sorted(registered_users)
    })


COMMAND_HANDLERS = {
    "register": handle_register,
    "get_user_key": handle_get_user_key,
    "publish_prekeys": handle_publish_prekeys,
    "get_prekey": handle_get_prekey,
    "send_message": handle_send_message,
    "relay_session_envelope": handle_relay_session_envelope,
    "fetch_messages": handle_fetch_messages,
    "ack_messages": handle_ack_messages,
    "list_contacts": handle_list_contacts,
    "update_contacts": handle_update_contacts,
    "list_groups": handle_list_groups,
    "update_groups": handle_update_groups,
    "list_users": handle_list_users,
}


def dispatch_command(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate):
    command = msg.get("command")
    handler = COMMAND_HANDLERS.get(command)
    if handler is None:
        send_json(conn, {"status": "error", "message": "comando desconhecido"})
        return None
    return handler(conn, msg, authenticated_username, authenticated_public_key, authenticated_certificate)
