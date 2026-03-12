import socket
import threading
from protocol import send_json, recv_json
from storage import load_users, save_users, load_messages, save_messages


HOST = "127.0.0.1"
PORT = 9000

online_users = {}  # username -> socket

REQUIRED_PAYLOAD_FIELDS = {"nonce", "ciphertext", "encrypted_key"}
REQUIRED_ENVELOPE_FIELDS = {
    "message_id",
    "timestamp",
    "from",
    "to",
    "payload",
    "signature",
}


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


def handle_client(conn, addr):
    username = None
    try:
        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            command = msg.get("command")

            if command == "register":
                users = load_users()
                username = msg["username"]
                users[username] = {
                    "public_key": msg["public_key"]
                }
                save_users(users)
                online_users[username] = conn
                send_json(conn, {"status": "ok", "message": f"user '{username}' registado"})

            elif command == "get_user_key":
                users = load_users()
                target = msg["target"]
                if target not in users:
                    send_json(conn, {"status": "error", "message": "utilizador não existe"})
                else:
                    send_json(conn, {
                        "status": "ok",
                        "target": target,
                        "public_key": users[target]["public_key"]
                    })

            elif command == "send_message":
                users = load_users()

                if not is_valid_envelope(msg):
                    send_json(conn, {"status": "error", "message": "envelope de mensagem inválido"})
                    continue

                if msg["to"] not in users:
                    send_json(conn, {"status": "error", "message": "destinatário não existe"})
                    continue

                if username is not None and msg["from"] != username:
                    send_json(conn, {"status": "error", "message": "remetente inconsistente com a sessão"})
                    continue

                envelope = store_encrypted_message(msg)

                target_socket = online_users.get(msg["to"])
                if target_socket:
                    send_json(target_socket, {
                        "command": "deliver_message",
                        **envelope
                    })

                send_json(conn, {
                    "status": "ok",
                    "message": "mensagem enviada",
                    "message_id": envelope["message_id"],
                    "stored_encrypted": True,
                })

            elif command == "fetch_messages":
                username = msg["username"]
                pending = pop_pending_messages(username)

                send_json(conn, {
                    "status": "ok",
                    "messages": pending
                })

            elif command == "list_users":
                users = load_users()
                send_json(conn, {
                    "status": "ok",
                    "users": sorted(users.keys())
                })

            else:
                send_json(conn, {"status": "error", "message": "comando desconhecido"})

    except Exception as e:
        print(f"Erro com {addr}: {e}")
    finally:
        if username and username in online_users:
            del online_users[username]
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Servidor a escutar em {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
