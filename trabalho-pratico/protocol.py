import base64
import json
import threading

from common.crypto import decrypt_message, encrypt_message


_STATE_LOCK = threading.Lock()
_RECV_BUFFERS = {}  # socket-id -> bytes
_SEND_LOCKS = {}    # socket-id -> threading.Lock
_SESSION_KEYS = {}  # socket-id -> bytes


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
        _SESSION_KEYS.pop(key, None)


def register_session_key(sock, session_key: bytes):
    if not isinstance(session_key, (bytes, bytearray)):
        raise TypeError("session_key deve ser bytes")
    if len(session_key) not in {16, 24, 32}:
        raise ValueError("session_key inválida para AES-GCM")

    with _STATE_LOCK:
        _SESSION_KEYS[_socket_key(sock)] = bytes(session_key)


def clear_session_key(sock):
    with _STATE_LOCK:
        _SESSION_KEYS.pop(_socket_key(sock), None)


def _get_session_key(sock):
    with _STATE_LOCK:
        return _SESSION_KEYS.get(_socket_key(sock))


def _send_frame(sock, obj: dict):
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    lock = _get_send_lock(sock)
    with lock:
        sock.sendall(data)


def send_secure_json(sock, session_key: bytes, obj: dict):
    plaintext = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    encrypted = encrypt_message(session_key, plaintext)

    _send_frame(
        sock,
        {
            "_secure": True,
            "data": base64.b64encode(encrypted).decode("ascii"),
        },
    )


def send_json(sock, obj: dict):
    session_key = _get_session_key(sock)
    if session_key is None:
        _send_frame(sock, obj)
    else:
        send_secure_json(sock, session_key, obj)


def _recv_frame(sock):
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


def recv_secure_json(sock, session_key: bytes):
    frame = _recv_frame(sock)
    if frame is None:
        return None

    if not isinstance(frame, dict) or frame.get("_secure") is not True:
        raise ValueError("secure frame esperado")

    payload_b64 = frame.get("data")
    if not isinstance(payload_b64, str):
        raise ValueError("secure frame inválido")

    try:
        encrypted = base64.b64decode(payload_b64.encode("ascii"))
        plaintext = decrypt_message(session_key, encrypted)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"erro ao decifrar secure frame: {exc}") from exc


def recv_json(sock):
    session_key = _get_session_key(sock)
    if session_key is None:
        return _recv_frame(sock)
    return recv_secure_json(sock, session_key)
