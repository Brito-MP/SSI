import socket
import threading
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from common.secure_channel import (
    HandshakeError,
    load_server_security_context,
    server_handshake,
)
from crypto_utils import (
    E2EE_MESSAGE_VERSION,
    GROUP_MESSAGE_TYPE,
    e2ee_public_key_binding_bytes,
    public_key_from_pem,
    public_key_to_pem,
    verify_protected_contacts,
    verify_protected_groups,
    verify_signature,
    x25519_public_key_from_pem,
)
from protocol import send_json, recv_json
from storage import (
    PROTECTED_CONTACTS_FIELD,
    PROTECTED_GROUPS_FIELD,
    load_users,
    users_lock,
    save_users,
    load_messages,
    messages_lock,
    save_messages,
    set_protected_contacts,
    set_protected_groups,
)


HOST = "127.0.0.1"
PORT = 9000

online_users = {}  # username -> socket
online_users_lock = threading.Lock()

E2EE_PUBLIC_KEY_FIELD = "e2ee_public_key"
E2EE_PUBLIC_KEY_SIGNATURE_FIELD = "e2ee_public_key_signature"
REQUIRED_V1_PAYLOAD_FIELDS = {"nonce", "ciphertext", "encrypted_key"}
REQUIRED_V2_PAYLOAD_FIELDS = {"version", "nonce", "ciphertext", "sender_ephemeral_key"}
REQUIRED_ENVELOPE_FIELDS = {
    "message_id",
    "timestamp",
    "from",
    "to",
    "payload",
    "signature",
}
OPTIONAL_ENVELOPE_FIELDS = {"group_id", "group_name", "group_members", "group_action"}
REQUIRED_GROUP_MESSAGE_FIELDS = {
    "type",
    "group_id",
    "message_id",
    "timestamp",
    "from",
    "to",
    "nonce",
    "ciphertext",
    "signature",
}


def is_valid_payload(payload: dict) -> bool:
    if not isinstance(payload, dict):
        return False

    if payload.get("version") == E2EE_MESSAGE_VERSION:
        return REQUIRED_V2_PAYLOAD_FIELDS.issubset(payload.keys()) and all(
            isinstance(payload[field], str)
            for field in ["nonce", "ciphertext", "sender_ephemeral_key"]
        )

    return REQUIRED_V1_PAYLOAD_FIELDS.issubset(payload.keys()) and all(
        isinstance(payload[field], str)
        for field in ["nonce", "ciphertext", "encrypted_key"]
    )


# Verifica se a estrutura da mensagem recebida tem o formato esperado.
def is_valid_envelope(msg: dict) -> bool:
    if msg.get("type") == GROUP_MESSAGE_TYPE:
        return REQUIRED_GROUP_MESSAGE_FIELDS.issubset(msg.keys()) and all(
            isinstance(msg[field], str) and msg[field]
            for field in REQUIRED_GROUP_MESSAGE_FIELDS
        )

    if not REQUIRED_ENVELOPE_FIELDS.issubset(msg.keys()):
        return False

    if not is_valid_payload(msg.get("payload")):
        return False

    if not all(isinstance(msg[field], str) for field in ["message_id", "timestamp", "from", "to", "signature"]):
        return False

    return True


# Guarda uma mensagem offline para o destinatário.
# O conteúdo já vem cifrado do cliente; o servidor só persiste e encaminha.
def build_envelope(msg: dict):
    if msg.get("type") == GROUP_MESSAGE_TYPE:
        return {
            "type": GROUP_MESSAGE_TYPE,
            "group_id": msg["group_id"],
            "message_id": msg["message_id"],
            "timestamp": msg["timestamp"],
            "from": msg["from"],
            "to": msg["to"],
            "nonce": msg["nonce"],
            "ciphertext": msg["ciphertext"],
            "signature": msg["signature"],
        }

    envelope = {
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
        "signature": msg["signature"],
    }
    for field in OPTIONAL_ENVELOPE_FIELDS:
        if field in msg:
            envelope[field] = msg[field]
    return envelope


def store_encrypted_message(msg: dict, envelope: dict | None = None):
    with messages_lock():
        messages = load_messages()
        if envelope is None:
            envelope = build_envelope(msg)
        messages.append(envelope)
        save_messages(messages)
    return envelope


def remove_online_user_if_socket(username: str, sock):
    with online_users_lock:
        if online_users.get(username) is sock:
            del online_users[username]


def deliver_or_store_message(msg: dict, users: dict):
    envelope = build_envelope(msg)
    target = msg["to"]

    with online_users_lock:
        target_socket = online_users.get(target)

    if target_socket is not None:
        try:
            send_json(target_socket, {
                "command": "deliver_message",
                "sender_public_key": sender_public_key(users, msg["from"]),
                "sender_certificate": sender_certificate(users, msg["from"]),
                **envelope,
            })
        except OSError:
            remove_online_user_if_socket(target, target_socket)
        else:
            return envelope, True, False

    store_encrypted_message(msg, envelope)
    return envelope, False, True


# Entrega mensagens pendentes de um utilizador e remove-as da fila offline.
def pop_pending_messages(username: str):
    with messages_lock():
        messages = load_messages()
        pending = [m for m in messages if m["to"] == username]
        remaining = [m for m in messages if m["to"] != username]
        save_messages(remaining)
    return pending


def sender_public_key(users: dict, sender: str):
    return users.get(sender, {}).get("public_key")


def sender_certificate(users: dict, sender: str):
    return users.get(sender, {}).get("certificate")


def enrich_with_sender_keys(messages, users: dict):
    enriched = []
    for msg in messages:
        enriched.append({
            **msg,
            "sender_public_key": sender_public_key(users, msg["from"]),
            "sender_certificate": sender_certificate(users, msg["from"]),
        })
    return enriched


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


def handle_client(conn, addr, security_ctx):
    username = None
    authenticated_username = None
    authenticated_public_key = None
    authenticated_certificate = None
    try:
        _, authenticated_username, authenticated_public_key, authenticated_certificate = server_handshake(conn, security_ctx)

        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            command = msg.get("command")

            if command == "register":
                with users_lock():
                    users = load_users()
                    requested_username = msg.get("username")
                    if requested_username != authenticated_username:
                        send_json(conn, {
                            "status": "error",
                            "message": "username não corresponde ao certificado autenticado",
                        })
                        continue

                    username = requested_username
                    try:
                        requested_public_key = canonical_public_key_pem(msg["public_key"])
                    except Exception:
                        send_json(conn, {"status": "error", "message": "chave pública inválida"})
                        continue

                    if requested_public_key != authenticated_public_key:
                        send_json(conn, {
                            "status": "error",
                            "message": "chave pública não corresponde ao certificado autenticado",
                        })
                        continue

                    try:
                        requested_e2ee_public_key = can_set_e2ee_public_key(
                            None,
                            msg[E2EE_PUBLIC_KEY_FIELD],
                        )
                    except KeyError:
                        send_json(conn, {"status": "error", "message": "chave pública E2EE em falta"})
                        continue
                    except Exception:
                        send_json(conn, {"status": "error", "message": "chave pública E2EE inválida"})
                        continue

                    requested_e2ee_public_key_signature = msg.get(E2EE_PUBLIC_KEY_SIGNATURE_FIELD)
                    if not isinstance(requested_e2ee_public_key_signature, str):
                        send_json(conn, {"status": "error", "message": "assinatura da chave pública E2EE em falta"})
                        continue

                    if not verify_signature(
                        e2ee_public_key_binding_bytes(username, requested_e2ee_public_key),
                        requested_e2ee_public_key_signature,
                        public_key_from_pem(requested_public_key),
                    ):
                        send_json(conn, {"status": "error", "message": "assinatura da chave pública E2EE inválida"})
                        continue

                    user_data = users.get(username, {})
                    if not isinstance(user_data, dict):
                        user_data = {}

                    existing_public_key = user_data.get("public_key")
                    if existing_public_key is not None:
                        try:
                            existing_public_key = canonical_public_key_pem(existing_public_key)
                        except Exception:
                            send_json(conn, {"status": "error", "message": "chave pública registada inválida"})
                            continue

                        if existing_public_key != requested_public_key:
                            send_json(conn, {
                                "status": "error",
                                "message": "utilizador já registado com outra chave pública",
                            })
                            continue

                    existing_e2ee_public_key = user_data.get(E2EE_PUBLIC_KEY_FIELD)
                    try:
                        requested_e2ee_public_key = can_set_e2ee_public_key(
                            existing_e2ee_public_key,
                            requested_e2ee_public_key,
                        )
                    except ValueError as exc:
                        send_json(conn, {"status": "error", "message": str(exc)})
                        continue
                    except Exception:
                        send_json(conn, {"status": "error", "message": "chave pública E2EE registada inválida"})
                        continue

                    user_data["public_key"] = requested_public_key
                    user_data[E2EE_PUBLIC_KEY_FIELD] = requested_e2ee_public_key
                    user_data[E2EE_PUBLIC_KEY_SIGNATURE_FIELD] = requested_e2ee_public_key_signature
                    user_data["certificate"] = authenticated_certificate
                    user_data.pop("contacts", None)
                    user_data.pop("groups", None)
                    users[username] = user_data
                    save_users(users)
                with online_users_lock:
                    online_users[username] = conn
                send_json(conn, {"status": "ok", "message": f"user '{username}' registado"})

            elif command == "get_user_key":
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
                    })

            elif command == "send_message":
                users = load_users()

                if not is_valid_envelope(msg):
                    send_json(conn, {"status": "error", "message": "envelope de mensagem inválido"})
                    continue

                if registered_user(users, msg["to"]) is None:
                    send_json(conn, {"status": "error", "message": "destinatário não existe"})
                    continue

                if msg["from"] != authenticated_username:
                    send_json(conn, {"status": "error", "message": "remetente inconsistente com a sessão"})
                    continue

                envelope, delivered_online, stored_encrypted = deliver_or_store_message(msg, users)

                send_json(conn, {
                    "status": "ok",
                    "message": "mensagem enviada",
                    "message_id": envelope["message_id"],
                    "stored_encrypted": stored_encrypted,
                    "delivered_online": delivered_online,
                })

            elif command == "fetch_messages":
                requested_username = msg.get("username")

                if requested_username != authenticated_username:
                    send_json(conn, {"status": "error", "message": "username inválido para esta sessão"})
                    continue

                if requested_username is None:
                    send_json(conn, {"status": "error", "message": "username em falta"})
                    continue

                pending = pop_pending_messages(requested_username)
                users = load_users()
                pending = enrich_with_sender_keys(pending, users)

                send_json(conn, {
                    "status": "ok",
                    "messages": pending
                })

            elif command == "list_contacts":
                users = load_users()
                user_data = registered_user(users, authenticated_username)
                if user_data is None:
                    send_json(conn, {"status": "error", "message": "utilizador não registado"})
                    continue

                send_json(conn, {
                    "status": "ok",
                    "protected_contacts": user_data.get(PROTECTED_CONTACTS_FIELD),
                })

            elif command == "update_contacts":
                with users_lock():
                    users = load_users()
                    user_data = registered_user(users, authenticated_username)
                    if user_data is None:
                        send_json(conn, {"status": "error", "message": "utilizador não registado"})
                        continue

                    protected_contacts = msg.get("protected_contacts")
                    try:
                        public_key = public_key_from_pem(user_data["public_key"])
                    except Exception:
                        send_json(conn, {"status": "error", "message": "chave pública do utilizador inválida"})
                        continue

                    if not verify_protected_contacts(protected_contacts, authenticated_username, public_key):
                        send_json(conn, {"status": "error", "message": "contactos protegidos inválidos"})
                        continue

                    set_protected_contacts(user_data, protected_contacts)
                    users[authenticated_username] = user_data
                    save_users(users)

                send_json(conn, {
                    "status": "ok",
                    "message": "contactos atualizados",
                    "protected_contacts": user_data[PROTECTED_CONTACTS_FIELD],
                })

            elif command == "list_groups":
                users = load_users()
                user_data = registered_user(users, authenticated_username)
                if user_data is None:
                    send_json(conn, {"status": "error", "message": "utilizador não registado"})
                    continue

                send_json(conn, {
                    "status": "ok",
                    "protected_groups": user_data.get(PROTECTED_GROUPS_FIELD),
                })

            elif command == "update_groups":
                with users_lock():
                    users = load_users()
                    user_data = registered_user(users, authenticated_username)
                    if user_data is None:
                        send_json(conn, {"status": "error", "message": "utilizador não registado"})
                        continue

                    protected_groups = msg.get("protected_groups")
                    try:
                        public_key = public_key_from_pem(user_data["public_key"])
                    except Exception:
                        send_json(conn, {"status": "error", "message": "chave pública do utilizador inválida"})
                        continue

                    if not verify_protected_groups(protected_groups, authenticated_username, public_key):
                        send_json(conn, {"status": "error", "message": "grupos protegidos inválidos"})
                        continue

                    set_protected_groups(user_data, protected_groups)
                    users[authenticated_username] = user_data
                    save_users(users)

                send_json(conn, {
                    "status": "ok",
                    "message": "grupos atualizados",
                    "protected_groups": user_data[PROTECTED_GROUPS_FIELD],
                })

            elif command == "list_users":
                users = load_users()
                registered_users = [user for user in users if registered_user(users, user) is not None]
                send_json(conn, {
                    "status": "ok",
                    "users": sorted(registered_users)
                })

            else:
                send_json(conn, {"status": "error", "message": "comando desconhecido"})

    except HandshakeError as exc:
        print(f"Handshake falhou com {addr}: {exc}")
    except Exception as e:
        print(f"Erro com {addr}: {e}")
    finally:
        if username:
            with online_users_lock:
                if online_users.get(username) is conn:
                    del online_users[username]
        conn.close()


def main():
    security_ctx = load_server_security_context()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
    except OSError as exc:
        print(f"Não foi possível abrir {HOST}:{PORT} ({exc}).")
        print("Confirma se já existe outro server.py a correr e termina-o.")
        server.close()
        return
    server.listen(5)
    print(f"Servidor a escutar em {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr, security_ctx), daemon=True).start()


if __name__ == "__main__":
    main()
