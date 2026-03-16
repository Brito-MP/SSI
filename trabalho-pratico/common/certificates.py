from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


ROOT_DIR = Path(__file__).resolve().parent.parent
CERTS_DIR = ROOT_DIR / "certs"
CLIENT_CERTS_DIR = CERTS_DIR / "clients"
KEYS_DIR = ROOT_DIR / "keys"

CA_CERT_PATH = CERTS_DIR / "ca_cert.pem"
SERVER_CERT_PATH = CERTS_DIR / "server_cert.pem"
SERVER_KEY_PATH = CERTS_DIR / "server_key.pem"


def _read_pem(path: Path, label: str) -> bytes:
    if not path.exists():
        raise FileNotFoundError(f"{label} não encontrado: {path}")
    return path.read_bytes()


def certificate_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def certificate_from_pem(pem_text: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem_text.encode("utf-8"))


def _load_certificate(path: Path, label: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(_read_pem(path, label))


def _load_private_key(path: Path, label: str):
    return serialization.load_pem_private_key(_read_pem(path, label), password=None)


def load_ca_certificate() -> x509.Certificate:
    return _load_certificate(CA_CERT_PATH, "certificado da CA")


def load_server_certificate() -> x509.Certificate:
    return _load_certificate(SERVER_CERT_PATH, "certificado do servidor")


def load_server_private_key():
    return _load_private_key(SERVER_KEY_PATH, "chave privada do servidor")


def load_client_certificate(username: str) -> x509.Certificate:
    cert_path = CLIENT_CERTS_DIR / f"{username}_cert.pem"
    return _load_certificate(cert_path, f"certificado do cliente '{username}'")


def load_client_private_key(username: str):
    key_path = KEYS_DIR / f"{username}_private.pem"
    return _load_private_key(key_path, f"chave privada do cliente '{username}'")
