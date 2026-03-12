import socket
import threading
from protocol import send_json, recv_json
from storage import load_users, save_users, load_messages, save_messages


HOST = "127.0.0.1"
PORT = 9000

online_users = {}  # username -> socket


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
                messages = load_messages()
                envelope = {
                    "from": msg["from"],
                    "to": msg["to"],
                    "payload": msg["payload"],
                    "signature": msg["signature"]
                }
                messages.append(envelope)
                save_messages(messages)

                target_socket = online_users.get(msg["to"])
                if target_socket:
                    send_json(target_socket, {
                        "command": "deliver_message",
                        **envelope
                    })

                send_json(conn, {"status": "ok", "message": "mensagem enviada"})

            elif command == "fetch_messages":
                username = msg["username"]
                messages = load_messages()
                pending = [m for m in messages if m["to"] == username]
                remaining = [m for m in messages if m["to"] != username]
                save_messages(remaining)

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