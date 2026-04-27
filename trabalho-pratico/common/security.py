from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


SERVER_COMMON_NAME = "SSI Chat Server"
CLIENT_COMMON_NAME_PREFIX = "SSI Chat Client - "


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _certificate_valid_now(cert: x509.Certificate) -> bool:
    not_before = getattr(cert, "not_valid_before_utc", None)
    not_after = getattr(cert, "not_valid_after_utc", None)

    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    if not_after is None:
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    now = _now_utc()
    return not_before <= now <= not_after


def _certificate_common_name(cert: x509.Certificate):
    try:
        return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except Exception:
        return None


def client_username_from_certificate(cert: x509.Certificate):
    cn = _certificate_common_name(cert)
    if cn is None or not cn.startswith(CLIENT_COMMON_NAME_PREFIX):
        return None

    username = cn[len(CLIENT_COMMON_NAME_PREFIX):]
    if not username:
        return None

    return username


def validate_certificate(cert, ca_cert, client_or_server):
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    except Exception:
        return False

    if not _certificate_valid_now(cert):
        return False

    cn = _certificate_common_name(cert)
    if cn is None:
        return False

    if client_or_server == 0:
        return client_username_from_certificate(cert) is not None
    if client_or_server == 1:
        return cn == SERVER_COMMON_NAME
    return False


def sign_dh_keys(private_key, dh_pub1: bytes, dh_pub2: bytes):
    data = dh_pub1 + dh_pub2
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def validate_signature(public_key, signature, dh_pub1: bytes, dh_pub2: bytes):
    data = dh_pub1 + dh_pub2
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
