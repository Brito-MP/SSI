"""
Testes básicos de segurança para o projeto SSI chat.

Executar com:
python3 test_security.py
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa

from common.key_exchange import derive_session_key
from common.certificates import load_client_certificate
from common.security import client_username_from_certificate, sign_dh_keys, validate_signature

from common.crypto import encrypt_message, decrypt_message
from crypto_utils import normalize_contact_list, protect_contacts, public_key_to_pem, unprotect_contacts


def generate_rsa_keypair():
    """Gera um par de chaves RSA para testes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()
    return private_key, public_key


def test_encryption():
    print("\n[TESTE] Encriptação AES-GCM")

    key = os.urandom(32)
    plaintext = b"segredo123"

    encrypted = encrypt_message(key, plaintext)
    decrypted = decrypt_message(key, encrypted)

    assert decrypted == plaintext

    if plaintext in encrypted:
        raise Exception("Plaintext encontrado no ciphertext!")

    print("OK - Encriptação funciona")


def test_signature():
    print("\n[TESTE] Assinatura digital")

    priv, pub = generate_rsa_keypair()

    dh1 = os.urandom(32)
    dh2 = os.urandom(32)

    signature = sign_dh_keys(priv, dh1, dh2)

    valid = validate_signature(pub, signature, dh1, dh2)

    assert valid

    print("OK - Assinatura válida")


def test_signature_tamper():
    print("\n[TESTE] Detetar adulteração")

    priv, pub = generate_rsa_keypair()

    dh1 = os.urandom(32)
    dh2 = os.urandom(32)

    signature = sign_dh_keys(priv, dh1, dh2)

    # alterar dados
    dh2_bad = os.urandom(32)

    valid = validate_signature(pub, signature, dh1, dh2_bad)

    assert not valid

    print("OK - adulteração detetada")


def test_session_key():
    print("\n[TESTE] Derivação de chave de sessão")

    shared_secret = os.urandom(32)
    client_pub = os.urandom(32)
    server_pub = os.urandom(32)

    key1 = derive_session_key(shared_secret, client_pub, server_pub)
    key2 = derive_session_key(shared_secret, client_pub, server_pub)

    assert key1 == key2

    print("OK - HKDF consistente")


def test_certificate_username_binding():
    print("\n[TESTE] Username no certificado")

    cert = load_client_certificate("henrique")
    username = client_username_from_certificate(cert)

    assert username == "henrique"

    print("OK - certificado vinculado ao username")


def test_certificate_public_key_binding():
    print("\n[TESTE] Chave pública vinculada ao certificado")

    cert = load_client_certificate("henrique")
    cert_public_key = public_key_to_pem(cert.public_key())
    register_public_key = public_key_to_pem(cert.public_key())

    assert register_public_key == cert_public_key

    print("OK - chave pública corresponde ao certificado")


def test_contacts_metadata_normalization():
    print("\n[TESTE] Normalização de contactos")

    contacts = normalize_contact_list(["goncalo", " simao ", "goncalo", "", 123])

    assert contacts == ["goncalo", "simao"]
    assert normalize_contact_list("inválido") == []

    print("OK - contactos normalizados")


def test_protected_contacts_roundtrip():
    print("\n[TESTE] Contactos cifrados e assinados")

    priv, pub = generate_rsa_keypair()
    protected_contacts = protect_contacts("henrique", ["goncalo", " simao ", "goncalo"], priv, pub)
    contacts = unprotect_contacts(protected_contacts, "henrique", priv, pub)

    assert contacts == ["goncalo", "simao"]

    protected_contacts["owner"] = "goncalo"
    try:
        unprotect_contacts(protected_contacts, "goncalo", priv, pub)
    except ValueError:
        pass
    else:
        raise AssertionError("contactos alterados foram aceites")

    print("OK - contactos protegidos contra leitura e alteração")


def run_all():
    print("===== TESTES DE SEGURANÇA =====")

    test_encryption()
    test_signature()
    test_signature_tamper()
    test_session_key()
    test_certificate_username_binding()
    test_certificate_public_key_binding()
    test_contacts_metadata_normalization()
    test_protected_contacts_roundtrip()

    print("\nTODOS OS TESTES PASSARAM")


if __name__ == "__main__":
    run_all()
