import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from protocol import recv_json
from handlers.message_handler import process_incoming_message


def listener_loop(sock, state):
    try:
        while not state.stop_event.is_set():
            msg = recv_json(sock)
            if msg is None:
                break

            if msg.get("command") == "deliver_message":
                process_incoming_message(msg, state)
            else:
                state.response_queue.put(msg)
    except Exception as exc:
        if not state.stop_event.is_set():
            print(f"[ERRO] listener terminou com erro: {exc}")
    finally:
        state.stop_event.set()
        state.response_queue.put({"_event": "disconnected"})
