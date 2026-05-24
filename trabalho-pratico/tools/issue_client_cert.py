from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from common.certificates import (  # noqa: E402
    CA_CERT_PATH,
    CERTS_DIR,
    CLIENT_CERTS_DIR,
    KEYS_DIR,
)
from common.security import CLIENT_COMMON_NAME_PREFIX  # noqa: E402
from crypto_utils import generate_rsa_keypair, save_private_key, save_public_key  # noqa: E402


USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
CERT_VALIDITY_DAYS = 3650


def validate_username(username: str):
    if not isinstance(username, str) or not username:
        raise ValueError("username inválido: não pode ser vazio")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("username inválido: usa apenas letras, números, '_' e '-'")
    return username


def project_paths(base_dir: Path | str | None = None):
    root = Path(base_dir) if base_dir is not None else PROJECT_DIR
    root = root.resolve()
    certs_dir = root / CERTS_DIR.relative_to(PROJECT_DIR)
    keys_dir = root / KEYS_DIR.relative_to(PROJECT_DIR)
    client_certs_dir = root / CLIENT_CERTS_DIR.relative_to(PROJECT_DIR)
    ca_cert_path = root / CA_CERT_PATH.relative_to(PROJECT_DIR)
    ca_key_path = certs_dir / "ca_key.pem"
    return root, certs_dir, keys_dir, client_certs_dir, ca_cert_path, ca_key_path


def load_certificate(path: Path, label: str):
    if not path.exists():
        raise FileNotFoundError(f"{label} não encontrado: {path}")
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_private_key(path: Path, label: str):
    if not path.exists():
        raise FileNotFoundError(f"{label} não encontrada: {path}")
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def ensure_no_overwrite(paths, force: bool):
    if force:
        return

    existing = [path for path in paths if path.exists()]
    if existing:
        names = ", ".join(str(path) for path in existing)
        raise FileExistsError(f"ficheiros já existentes: {names}. Usa --force para sobrescrever.")


def build_client_certificate(username: str, public_key, ca_cert, ca_private_key):
    now = datetime.datetime.now(datetime.timezone.utc)
    common_name = f"{CLIENT_COMMON_NAME_PREFIX}{username}"
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )


def issue_client_certificate(username, force=False, base_dir=None):
    username = validate_username(username)
    _, _, keys_dir, client_certs_dir, ca_cert_path, ca_key_path = project_paths(base_dir)

    private_key_path = keys_dir / f"{username}_private.pem"
    public_key_path = keys_dir / f"{username}_public.pem"
    cert_path = client_certs_dir / f"{username}_cert.pem"
    output_paths = [private_key_path, public_key_path, cert_path]

    ensure_no_overwrite(output_paths, force)

    ca_cert = load_certificate(ca_cert_path, "certificado da CA")
    ca_private_key = load_private_key(ca_key_path, "chave privada da CA")

    keys_dir.mkdir(parents=True, exist_ok=True)
    client_certs_dir.mkdir(parents=True, exist_ok=True)

    private_key, public_key = generate_rsa_keypair()
    cert = build_client_certificate(username, public_key, ca_cert, ca_private_key)

    save_private_key(private_key, str(private_key_path))
    save_public_key(public_key, str(public_key_path))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    return {
        "username": username,
        "private_key_path": private_key_path,
        "public_key_path": public_key_path,
        "cert_path": cert_path,
    }


def relative_to_base(path: Path, base_dir: Path):
    try:
        return path.relative_to(base_dir)
    except ValueError:
        return path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Emite offline um certificado X.509 de cliente assinado pela CA local.",
    )
    parser.add_argument("username")
    parser.add_argument("--force", action="store_true", help="sobrescreve ficheiros existentes desse username")
    args = parser.parse_args(argv)

    try:
        result = issue_client_certificate(args.username, force=args.force)
    except Exception as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1

    base_dir = PROJECT_DIR.resolve()
    print(f"Certificado emitido para {result['username']}.")
    print("Ficheiros criados:")
    print(f"- {relative_to_base(result['private_key_path'], base_dir)}")
    print(f"- {relative_to_base(result['public_key_path'], base_dir)}")
    print(f"- {relative_to_base(result['cert_path'], base_dir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
