import socket
import sys
import threading
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
SERVER_DIR = Path(__file__).resolve().parent
server_dir_text = str(SERVER_DIR)
if server_dir_text in sys.path:
    sys.path.remove(server_dir_text)
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from common.secure_channel import HandshakeError, load_server_security_context, server_handshake
from protocol import recv_json
from server.command_handlers import COMMAND_HANDLERS, dispatch_command
from server.message_store import (
    ack_pending_messages,
    build_envelope,
    deliver_or_store_message,
    enrich_with_sender_keys,
    get_pending_messages,
    store_encrypted_message,
)
from server.prekey_store import clean_public_signed_prekey, pop_available_signed_prekey, publish_signed_prekeys_for_user
from server.server_common import (
    E2EE_PUBLIC_KEY_FIELD,
    E2EE_PUBLIC_KEY_SIGNATURE_FIELD,
    HOST,
    MAX_SIGNED_PREKEYS_PER_USER,
    ONLINE_ONLY_MESSAGE_TYPES,
    PORT,
    SIGNED_PREKEYS_FIELD,
)
from server.server_state import online_users, online_users_lock, remove_online_user_if_socket
from server.user_store import (
    can_set_e2ee_public_key,
    canonical_e2ee_public_key_pem,
    canonical_public_key_pem,
    registered_user,
    sender_certificate,
    sender_public_key,
)
from server.validators import (
    FORBIDDEN_PLAINTEXT_GROUP_FIELDS,
    OPTIONAL_ENVELOPE_FIELDS,
    REQUIRED_ENVELOPE_FIELDS,
    REQUIRED_GROUP_MESSAGE_FIELDS,
    REQUIRED_OFFLINE_PREKEY_MESSAGE_FIELDS,
    REQUIRED_ONLINE_SESSION_MESSAGE_FIELDS,
    REQUIRED_SESSION_HANDSHAKE_FIELDS,
    REQUIRED_V1_PAYLOAD_FIELDS,
    REQUIRED_V2_PAYLOAD_FIELDS,
    is_valid_envelope,
    is_valid_group_payload,
    is_valid_offline_prekey_payload,
    is_valid_online_session_message,
    is_valid_payload,
    is_valid_session_handshake,
)


def handle_client(conn, addr, security_ctx):
    username = None
    try:
        _, authenticated_username, authenticated_public_key, authenticated_certificate = server_handshake(conn, security_ctx)

        while True:
            msg = recv_json(conn)
            if msg is None:
                break

            registered_username = dispatch_command(
                conn,
                msg,
                authenticated_username,
                authenticated_public_key,
                authenticated_certificate,
            )
            if registered_username:
                username = registered_username

    except HandshakeError as exc:
        print(f"Handshake falhou com {addr}: {exc}")
    except Exception as e:
        print(f"Erro com {addr}: {e}")
    finally:
        if username:
            remove_online_user_if_socket(username, conn)
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
