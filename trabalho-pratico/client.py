import os
import socket
from protocol import send_json, recv_json
from crypto_utils import (
    generate_rsa_keypair,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
    public_key_to_pem,
    public_key_from_pem,
    encrypt_for_recipient,
    decrypt_from_sender,
    sign_message,
    verify_signature,
    canonical_message_bytes,
    generate_message_id,
    utc_timestamp,
)


HOST = "127.0.0.1"
PORT = 9000


# Garante que o utilizador tem par de chaves local.
# As chaves privadas ficam apenas na pasta local do cliente.
def ensure_keys(username: str):
    os.makedirs("keys", exist_ok=True)
    priv_path = f"keys/{username}_private.pem"
    pub_path = f"keys/{username}_public.pem"

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        private_key, public_key = generate_rsa_keypair()
        save_private_key(private_key, priv_path)
        save_public_key(public_key, pub_path)

    return load_private_key(priv_path), load_public_key(pub_path)


def register(sock, username, public_key):
    send_json(sock, {
        "command": "register",
        "username": username,
        "public_key": public_key_to_pem(public_key)
    })
    print(recv_json(sock))


def list_users(sock):
    send_json(sock, {"command": "list_users"})
    resp = recv_json(sock)
    print("Users:", resp.get("users", []))


def get_user_key(sock, username):
    send_json(sock, {"command": "get_user_key", "target": username})
    resp = recv_json(sock)
    if resp["status"] != "ok":
        print(resp["message"])
        return None
    return public_key_from_pem(resp["public_key"])


# Cria um envelope formal com os metadados necessários para a mensagem.
def build_message_envelope(my_username, target, text, my_private_key, target_public_key):
    payload = encrypt_for_recipient(text, target_public_key)

    envelope_to_sign = {
        "message_id": generate_message_id(),
        "timestamp": utc_timestamp(),
        "from": my_username,
        "to": target,
        "payload": payload,
    }

    signature = sign_message(canonical_message_bytes(envelope_to_sign), my_private_key)

    return {
        **envelope_to_sign,
        "signature": signature,
    }


def send_message(sock, my_username, my_private_key, target, text):
    target_public_key = get_user_key(sock, target)
    if target_public_key is None:
        return

    envelope = build_message_envelope(my_username, target, text, my_private_key, target_public_key)

    send_json(sock, {
        "command": "send_message",
        **envelope,
    })

    response = recv_json(sock)
    if response and response.get("status") == "ok":
        print(f"Mensagem enviada com sucesso. message_id={response.get('message_id')}")
    else:
        print(response)


# Valida a assinatura do remetente e só depois tenta decifrar a mensagem.
def display_verified_message(sock, msg, my_private_key):
    sender = msg["from"]

    sender_key = get_user_key(sock, sender)
    if sender_key is None:
        print(f"Não foi possível obter a chave pública de {sender}")
        return

    signed_part = {
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "payload": msg["payload"],
    }

    valid = verify_signature(
        canonical_message_bytes(signed_part),
        msg["signature"],
        sender_key
    )

    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem {msg.get('message_id')}")
        return

    try:
        plaintext = decrypt_from_sender(msg["payload"], my_private_key)
        print(f"[{msg['timestamp']}] {sender} ({msg['message_id']}): {plaintext}")
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar a mensagem {msg.get('message_id')}: {exc}")


def fetch_messages(sock, username, my_private_key):
    send_json(sock, {"command": "fetch_messages", "username": username})
    resp = recv_json(sock)

    messages = resp.get("messages", [])
    if not messages:
        print("Sem mensagens pendentes.")
        return

    for msg in messages:
        display_verified_message(sock, msg, my_private_key)


def main():
    username = input("Username: ").strip()
    private_key, public_key = ensure_keys(username)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    register(sock, username, public_key)

    while True:
        cmd = input("> ").strip()

        if cmd == "list":
            list_users(sock)

        elif cmd.startswith("send "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Uso: send <user> <mensagem>")
                continue
            _, target, text = parts
            send_message(sock, username, private_key, target, text)

        elif cmd == "inbox":
            fetch_messages(sock, username, private_key)

        elif cmd == "exit":
            break

        else:
            print("Comandos: list | send <user> <mensagem> | inbox | exit")

    sock.close()


if __name__ == "__main__":
    main()
