import socket
import threading

from chat_state import ChatState
from chat_ui import print_main_help, run_ui_loop
from client_connection import connect_to_server, send_request
from client_worker import listener_loop
from common.secure_channel import (
    HandshakeError,
    client_handshake,
    load_client_security_context,
)
from crypto_utils import e2ee_public_key_binding_bytes, public_key_to_pem, sign_message
from handlers.contact_handler import sync_contacts
from handlers.message_handler import sync_groups, sync_pending_messages, update_groups
from handlers.prekey_handler import publish_signed_prekeys


def initialize_logged_in_client(state):
    publish_signed_prekeys(state)
    sync_contacts(state)
    sync_groups(state)
    sync_pending_messages(state, announce=True)


def main():
    username = input("Username: ").strip()
    if not username:
        print("Username inválido.")
        return

    state = ChatState.create(username)
    try:
        state.sock = connect_to_server()
    except OSError:
        print("Server is offline. Check if server.py is running.")
        return

    try:
        client_security = load_client_security_context(username=state.username)
        state.session_key = client_handshake(state.sock, client_security)
    except HandshakeError as exc:
        print(f"Handshake autenticado falhou: {exc}")
        state.stop_event.set()
        state.sock.close()
        return

    listener = threading.Thread(
        target=listener_loop,
        args=(state.sock, state),
        daemon=True,
    )
    listener.start()

    e2ee_public_key_pem = public_key_to_pem(state.x25519_public_key)
    register_resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {
            "command": "register",
            "username": state.username,
            "public_key": public_key_to_pem(state.public_key),
            "e2ee_public_key": e2ee_public_key_pem,
            "e2ee_public_key_signature": sign_message(
                e2ee_public_key_binding_bytes(state.username, e2ee_public_key_pem),
                state.private_key,
            ),
        },
    )

    if register_resp is None:
        print("Não foi possível registar: ligação perdida.")
        state.stop_event.set()
    elif register_resp.get("status") != "ok":
        print(register_resp.get("message", "erro no registo"))
        state.stop_event.set()
    else:
        initialize_logged_in_client(state)
        print(register_resp.get("message", "registo concluído"))
        print_main_help()

    try:
        run_ui_loop(state)
    except KeyboardInterrupt:
        pass
    finally:
        if state.groups_dirty and not state.stop_event.is_set():
            update_groups(state)
        with state.online_sessions_lock:
            state.online_sessions.clear()
            state.pending_online_sessions.clear()
        state.stop_event.set()
        try:
            state.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        state.sock.close()
        listener.join(timeout=1)


if __name__ == "__main__":
    main()
