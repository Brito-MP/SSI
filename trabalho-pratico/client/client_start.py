import socket
import threading

from chat_state import ChatState
from chat_ui import print_main_help, run_ui_loop
from client_connection import connect_to_server, send_request
from client_worker import listener_loop
from crypto_utils import public_key_to_pem
from handlers.contact_handler import load_contacts


def main():
    username = input("Username: ").strip()
    if not username:
        print("Username inválido.")
        return

    state = ChatState.create(username)
    state.contacts = load_contacts(username)
    state.sock = connect_to_server()

    listener = threading.Thread(
        target=listener_loop,
        args=(state.sock, state),
        daemon=True,
    )
    listener.start()

    register_resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {
            "command": "register",
            "username": state.username,
            "public_key": public_key_to_pem(state.public_key),
        },
    )

    if register_resp is None:
        print("Não foi possível registar: ligação perdida.")
        state.stop_event.set()
    elif register_resp.get("status") != "ok":
        print(register_resp.get("message", "erro no registo"))
        state.stop_event.set()
    else:
        print(register_resp.get("message", "registo concluído"))
        print_main_help()

    try:
        run_ui_loop(state)
    except KeyboardInterrupt:
        pass
    finally:
        state.stop_event.set()
        try:
            state.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        state.sock.close()
        listener.join(timeout=1)


if __name__ == "__main__":
    main()
