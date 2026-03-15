import queue
import socket
import sys
import threading
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from protocol import send_json


HOST = "127.0.0.1"
PORT = 9000
RESPONSE_TIMEOUT = 15


def connect_to_server(host: str = HOST, port: int = PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return sock


def wait_response(response_queue: queue.Queue, stop_event: threading.Event, timeout=RESPONSE_TIMEOUT):
    deadline = time.time() + timeout
    while not stop_event.is_set():
        remaining = deadline - time.time()
        if remaining <= 0:
            return None

        try:
            msg = response_queue.get(timeout=min(0.2, remaining))
        except queue.Empty:
            continue

        if msg.get("_event") == "disconnected":
            stop_event.set()
            return None

        return msg

    return None


def send_request(sock, response_queue, stop_event, payload, timeout=RESPONSE_TIMEOUT):
    send_json(sock, payload)
    return wait_response(response_queue, stop_event, timeout=timeout)
