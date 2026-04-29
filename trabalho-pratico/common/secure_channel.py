from __future__ import annotations

import base64
from dataclasses import dataclass

from common.certificates import (
    certificate_from_pem,
    certificate_to_pem,
    load_ca_certificate,
    load_client_certificate,
    load_client_private_key,
    load_server_certificate,
    load_server_private_key,
)
from common.key_exchange import (
    derive_session_key,
    generate_ephemeral_keypair,
    load_ephemeral_public_key,
)
from common.security import (
    client_username_from_certificate,
    sign_dh_keys,
    validate_certificate,
    validate_signature,
)
from crypto_utils import public_key_to_pem
from protocol import clear_session_key, recv_json, register_session_key, send_json


HANDSHAKE_CLIENT_HELLO = "secure_handshake_client_hello"
HANDSHAKE_SERVER_HELLO = "secure_handshake_server_hello"
HANDSHAKE_CLIENT_FINISH = "secure_handshake_client_finish"
HANDSHAKE_OK = "secure_handshake_ok"
HANDSHAKE_ERROR = "secure_handshake_error"


class HandshakeError(Exception):
    pass


@dataclass(frozen=True)
class ServerSecurityContext:
    ca_cert: object
    server_cert: object
    server_private_key: object


@dataclass(frozen=True)
class ClientSecurityContext:
    username: str
    ca_cert: object
    client_cert: object
    client_private_key: object


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def load_server_security_context() -> ServerSecurityContext:
    ca_cert = load_ca_certificate()
    server_cert = load_server_certificate()
    server_key = load_server_private_key()
    return ServerSecurityContext(
        ca_cert=ca_cert,
        server_cert=server_cert,
        server_private_key=server_key,
    )


def load_client_security_context(username: str) -> ClientSecurityContext:
    ca_cert = load_ca_certificate()
    client_cert = load_client_certificate(username)
    client_private_key = load_client_private_key(username)
    return ClientSecurityContext(
        username=username,
        ca_cert=ca_cert,
        client_cert=client_cert,
        client_private_key=client_private_key,
    )


def _send_handshake_error(sock, message: str):
    try:
        send_json(sock, {"command": HANDSHAKE_ERROR, "message": message})
    except Exception:
        pass


def _require_fields(payload: dict, required_fields: set[str], context: str):
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HandshakeError(f"{context}: campos em falta: {', '.join(sorted(missing))}")


def server_handshake(sock, security_ctx: ServerSecurityContext):
    clear_session_key(sock)

    try:
        client_hello = recv_json(sock)
        if client_hello is None:
            raise HandshakeError("cliente desligou durante client_hello")

        if client_hello.get("command") != HANDSHAKE_CLIENT_HELLO:
            raise HandshakeError("primeira mensagem não é secure_handshake_client_hello")

        _require_fields(client_hello, {"client_cert", "client_ephemeral_key"}, "client_hello")
        client_cert = certificate_from_pem(client_hello["client_cert"])

        if not validate_certificate(client_cert, security_ctx.ca_cert, client_or_server=0):
            raise HandshakeError("certificado do cliente inválido")
        authenticated_username = client_username_from_certificate(client_cert)
        authenticated_public_key = public_key_to_pem(client_cert.public_key())
        authenticated_certificate = certificate_to_pem(client_cert)

        client_ephemeral_pub = _b64d(client_hello["client_ephemeral_key"])
        load_ephemeral_public_key(client_ephemeral_pub)  # valida tamanho/formato

        server_ephemeral_priv, server_ephemeral_pub = generate_ephemeral_keypair()
        server_signature = sign_dh_keys(
            security_ctx.server_private_key,
            server_ephemeral_pub,
            client_ephemeral_pub,
        )

        send_json(
            sock,
            {
                "command": HANDSHAKE_SERVER_HELLO,
                "server_cert": certificate_to_pem(security_ctx.server_cert),
                "server_ephemeral_key": _b64e(server_ephemeral_pub),
                "signature": _b64e(server_signature),
            },
        )

        client_finish = recv_json(sock)
        if client_finish is None:
            raise HandshakeError("cliente desligou durante client_finish")

        if client_finish.get("command") != HANDSHAKE_CLIENT_FINISH:
            raise HandshakeError("mensagem esperada secure_handshake_client_finish")

        _require_fields(client_finish, {"signature"}, "client_finish")
        client_signature = _b64d(client_finish["signature"])

        if not validate_signature(
            client_cert.public_key(),
            client_signature,
            client_ephemeral_pub,
            server_ephemeral_pub,
        ):
            raise HandshakeError("assinatura efémera do cliente inválida")

        shared_secret = server_ephemeral_priv.exchange(load_ephemeral_public_key(client_ephemeral_pub))
        session_key = derive_session_key(shared_secret, client_ephemeral_pub, server_ephemeral_pub)

        send_json(sock, {"command": HANDSHAKE_OK})
        register_session_key(sock, session_key)
        return session_key, authenticated_username, authenticated_public_key, authenticated_certificate

    except HandshakeError as exc:
        _send_handshake_error(sock, str(exc))
        raise
    except Exception as exc:
        _send_handshake_error(sock, "erro interno no handshake")
        raise HandshakeError(f"erro inesperado no handshake: {exc}") from exc


def client_handshake(sock, security_ctx: ClientSecurityContext) -> bytes:
    clear_session_key(sock)

    client_ephemeral_priv, client_ephemeral_pub = generate_ephemeral_keypair()

    send_json(
        sock,
        {
            "command": HANDSHAKE_CLIENT_HELLO,
            "client_cert": certificate_to_pem(security_ctx.client_cert),
            "client_ephemeral_key": _b64e(client_ephemeral_pub),
        },
    )

    server_hello = recv_json(sock)
    if server_hello is None:
        raise HandshakeError("ligação fechada durante server_hello")

    if server_hello.get("command") == HANDSHAKE_ERROR:
        raise HandshakeError(server_hello.get("message", "erro no handshake"))

    if server_hello.get("command") != HANDSHAKE_SERVER_HELLO:
        raise HandshakeError("mensagem esperada secure_handshake_server_hello")

    _require_fields(server_hello, {"server_cert", "server_ephemeral_key", "signature"}, "server_hello")

    server_cert = certificate_from_pem(server_hello["server_cert"])
    if not validate_certificate(server_cert, security_ctx.ca_cert, client_or_server=1):
        raise HandshakeError("certificado do servidor inválido")

    server_ephemeral_pub = _b64d(server_hello["server_ephemeral_key"])
    load_ephemeral_public_key(server_ephemeral_pub)  # valida tamanho/formato
    server_signature = _b64d(server_hello["signature"])

    if not validate_signature(
        server_cert.public_key(),
        server_signature,
        server_ephemeral_pub,
        client_ephemeral_pub,
    ):
        raise HandshakeError("assinatura efémera do servidor inválida")

    client_signature = sign_dh_keys(
        security_ctx.client_private_key,
        client_ephemeral_pub,
        server_ephemeral_pub,
    )

    send_json(
        sock,
        {
            "command": HANDSHAKE_CLIENT_FINISH,
            "signature": _b64e(client_signature),
        },
    )

    server_ok = recv_json(sock)
    if server_ok is None:
        raise HandshakeError("ligação fechada após client_finish")

    if server_ok.get("command") == HANDSHAKE_ERROR:
        raise HandshakeError(server_ok.get("message", "erro no handshake"))

    if server_ok.get("command") != HANDSHAKE_OK:
        raise HandshakeError("mensagem esperada secure_handshake_ok")

    shared_secret = client_ephemeral_priv.exchange(load_ephemeral_public_key(server_ephemeral_pub))
    session_key = derive_session_key(shared_secret, client_ephemeral_pub, server_ephemeral_pub)
    register_session_key(sock, session_key)
    return session_key
