import json


def send_json(sock, obj: dict):
    data = json.dumps(obj).encode() + b"\n"
    sock.sendall(data)


def recv_json(sock):
    buffer = b""
    while not buffer.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buffer += chunk
    return json.loads(buffer.decode())