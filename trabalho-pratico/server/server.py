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
from crypto_utils import public_key_from_pem, public_key_to_pem, verify_protected_contacts, verify_protected_groups
from protocol import send_json, recv_json
from storage import (
    PROTECTED_CONTACTS_FIELD,
    PROTECTED_GROUPS_FIELD,
    load_users,
    save_users,
    load_messages,
    save_messages,
    set_protected_contacts,
    set_protected_groups,
)


HOST = "127.0.0.1"
PORT = 9000

online_users = {}  # username -> socket
online_users_lock = threading.Lock()

REQUIRED_PAYLOAD_FIELDS = {"nonce", "ciphertext", "encrypted_key"}
REQUIRED_ENVELOPE_FIELDS = {
    "message_id",
    "timestamp",
    "from",
    "to",
    "payload",
    "signature",
}
OPTIONAL_ENVELOPE_FIELDS = {"group_id", "group_name", "group_members", "group_action"}


# Verifica se a estrutura da mensagem recebida tem o formato esperado.
def is_valid_envelope(msg: dict) -> bool:
    if not REQUIRED_ENVELOPE_FIELDS.issubset(msg.keys()):
        return False

    if not isinstance(msg.get("payload"), dict):
        return False

    if not REQUIRED_PAYLOAD_FIELDS.issubset(msg["payload"].keys()):
        return False

    if not all(isinstance(msg[field], str) for field in ["message_id", "timestamp", "from", "to", "signature"]):
        return False

    return True


# Guarda uma mensagem offline para o destinatário.
# O conteúdo já vem cifrado do cliente; o servidor só persiste e encaminha.
def store_encrypted_message(msg: dict):
    messages = load_messages()
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
    messages.append(envelope)
    save_messages(messages)
    return envelope


# Entrega mensagens pendentes de um utilizador e remove-as da fila offline.
def pop_pending_messages(username: str):
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

                user_data["public_key"] = requested_public_key
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

                envelope = store_encrypted_message(msg)
                sender_pub_key = sender_public_key(users, msg["from"])

                with online_users_lock:
                    target_socket = online_users.get(msg["to"])
                if target_socket:
                    send_json(target_socket, {
                        "command": "deliver_message",
                        "sender_public_key": sender_pub_key,
                        "sender_certificate": sender_certificate(users, msg["from"]),
                        **envelope
                    })

                send_json(conn, {
                    "status": "ok",
                    "message": "mensagem enviada",
                    "message_id": envelope["message_id"],
                    "stored_encrypted": True,
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
                if username in online_users:
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
