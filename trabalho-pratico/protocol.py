import json
import threading


_STATE_LOCK = threading.Lock()
_RECV_BUFFERS = {}  # socket-id -> bytes
_SEND_LOCKS = {}    # socket-id -> threading.Lock


def _socket_key(sock) -> int:
    return id(sock)


def _get_send_lock(sock) -> threading.Lock:
    key = _socket_key(sock)
    with _STATE_LOCK:
        lock = _SEND_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _SEND_LOCKS[key] = lock
        return lock


def _cleanup_socket_state(sock):
    key = _socket_key(sock)
    with _STATE_LOCK:
        _RECV_BUFFERS.pop(key, None)
        _SEND_LOCKS.pop(key, None)


def send_json(sock, obj: dict):
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    lock = _get_send_lock(sock)
    with lock:
        sock.sendall(data)


def recv_json(sock):
    key = _socket_key(sock)

    with _STATE_LOCK:
        buffer = _RECV_BUFFERS.get(key, b"")

    while True:
        if b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            with _STATE_LOCK:
                _RECV_BUFFERS[key] = buffer

            if not line.strip():
                continue

            try:
                return json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON frame: {exc}") from exc

        chunk = sock.recv(4096)
        if not chunk:
            _cleanup_socket_state(sock)
            return None
        buffer += chunk
