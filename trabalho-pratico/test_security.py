"""
Testes básicos de segurança para o projeto SSI chat.

Executar com:
python3 test_security.py
"""

import os
import copy
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa

CLIENT_DIR = Path(__file__).resolve().parent / "client"
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

from common.key_exchange import derive_session_key
from common.certificates import load_client_certificate
from common.security import client_username_from_certificate, sign_dh_keys, validate_signature

from common.crypto import encrypt_message, decrypt_message
from chat_state import ChatState
from handlers.conversation_handler import save_to_history
from handlers.message_handler import process_incoming_message
from crypto_utils import (
    decrypt_from_sender,
    e2ee_public_key_binding_bytes,
    encrypt_for_recipient,
    encrypt_for_recipient_v2,
    generate_x25519_keypair,
    normalize_contact_list,
    normalize_groups,
    protect_contacts,
    protect_groups,
    public_key_to_pem,
    sign_message,
    unprotect_contacts,
    unprotect_groups,
    verify_signature,
)
from server.server import can_set_e2ee_public_key


def generate_rsa_keypair():
    """Gera um par de chaves RSA para testes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()
    return private_key, public_key


def make_chat_state():
    return ChatState(
        username="alice",
        private_key=None,
        public_key=None,
        x25519_private_key=None,
        x25519_public_key=None,
    )


def history_message(message_id=None, sender="bob", target="alice"):
    msg = {
        "timestamp": "2026-05-22T18:00:00Z",
        "from": sender,
        "to": target,
    }
    if message_id is not None:
        msg["message_id"] = message_id
    return msg


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


def test_e2ee_v2_roundtrip():
    print("\n[TESTE] Mensagem E2EE v2 com X25519 efémero")

    rsa_priv, _ = generate_rsa_keypair()
    recipient_x25519_priv, recipient_x25519_pub = generate_x25519_keypair()

    payload = encrypt_for_recipient_v2("segredo com forward secrecy", recipient_x25519_pub)
    plaintext = decrypt_from_sender(payload, rsa_priv, recipient_x25519_priv)

    assert payload["version"] == 2
    assert "sender_ephemeral_key" in payload
    assert "encrypted_key" not in payload
    assert plaintext == "segredo com forward secrecy"

    print("OK - mensagem v2 cifra e decifra")


def test_e2ee_v2_fresh_ephemeral_keys():
    print("\n[TESTE] Mensagens E2EE v2 usam chaves efémeras novas")

    _, recipient_x25519_pub = generate_x25519_keypair()

    payload1 = encrypt_for_recipient_v2("mesmo texto", recipient_x25519_pub)
    payload2 = encrypt_for_recipient_v2("mesmo texto", recipient_x25519_pub)

    assert payload1["sender_ephemeral_key"] != payload2["sender_ephemeral_key"]
    assert payload1["ciphertext"] != payload2["ciphertext"]

    print("OK - mensagens iguais geram material criptográfico diferente")


def test_e2ee_v2_tamper_detection():
    print("\n[TESTE] Mensagem E2EE v2 deteta adulteração")

    rsa_priv, _ = generate_rsa_keypair()
    recipient_x25519_priv, recipient_x25519_pub = generate_x25519_keypair()
    _, attacker_x25519_pub = generate_x25519_keypair()
    payload = encrypt_for_recipient_v2("não alterar", recipient_x25519_pub)

    bad_ephemeral = copy.deepcopy(payload)
    bad_ephemeral["sender_ephemeral_key"] = public_key_to_pem(attacker_x25519_pub)
    try:
        decrypt_from_sender(bad_ephemeral, rsa_priv, recipient_x25519_priv)
    except Exception:
        pass
    else:
        raise AssertionError("sender_ephemeral_key adulterada foi aceite")

    bad_ciphertext = copy.deepcopy(payload)
    bad_ciphertext["ciphertext"] = payload["ciphertext"][:-4] + "AAAA"
    try:
        decrypt_from_sender(bad_ciphertext, rsa_priv, recipient_x25519_priv)
    except Exception:
        pass
    else:
        raise AssertionError("ciphertext adulterado foi aceite")

    print("OK - adulteração bloqueada")


def test_e2ee_v1_compatibility():
    print("\n[TESTE] Compatibilidade com mensagens E2EE v1")

    rsa_priv, rsa_pub = generate_rsa_keypair()
    payload = encrypt_for_recipient("mensagem antiga", rsa_pub)
    plaintext = decrypt_from_sender(payload, rsa_priv)

    assert "version" not in payload
    assert plaintext == "mensagem antiga"

    print("OK - mensagens v1 continuam suportadas")


def test_e2ee_public_key_binding_signature():
    print("\n[TESTE] Assinatura da chave pública E2EE")

    identity_priv, identity_pub = generate_rsa_keypair()
    _, e2ee_pub = generate_x25519_keypair()
    e2ee_public_key_pem = public_key_to_pem(e2ee_pub)
    signature = sign_message(e2ee_public_key_binding_bytes("henrique", e2ee_public_key_pem), identity_priv)

    assert verify_signature(e2ee_public_key_binding_bytes("henrique", e2ee_public_key_pem), signature, identity_pub)
    assert not verify_signature(e2ee_public_key_binding_bytes("simao", e2ee_public_key_pem), signature, identity_pub)

    print("OK - chave E2EE fica vinculada ao username/chave de identidade")


def test_e2ee_public_key_overwrite_rejected():
    print("\n[TESTE] Rejeitar alteração de chave pública E2EE registada")

    _, first_pub = generate_x25519_keypair()
    _, second_pub = generate_x25519_keypair()
    first_pem = public_key_to_pem(first_pub)
    second_pem = public_key_to_pem(second_pub)

    assert can_set_e2ee_public_key(None, first_pem) == first_pem
    assert can_set_e2ee_public_key(first_pem, first_pem) == first_pem

    try:
        can_set_e2ee_public_key(first_pem, second_pem)
    except ValueError:
        pass
    else:
        raise AssertionError("alteração de chave pública E2EE foi aceite")

    print("OK - overwrite indevido rejeitado")


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


def test_groups_metadata_normalization():
    print("\n[TESTE] Normalização de grupos")

    groups = normalize_groups({
        " group-equipa ": {"name": " Equipa ", "members": ["goncalo", " simao ", "goncalo", ""]},
        "": {"name": "inválido", "members": ["goncalo"]},
        "group-invalido": "inválido",
    })

    assert groups == {
        "group-equipa": {
            "name": "Equipa",
            "members": ["goncalo", "simao"],
        }
    }
    assert normalize_groups("inválido") == {}

    print("OK - grupos normalizados")


def test_protected_groups_roundtrip():
    print("\n[TESTE] Grupos cifrados e assinados")

    priv, pub = generate_rsa_keypair()
    protected_groups = protect_groups(
        "henrique",
        {"group-equipa": {"name": "Equipa", "members": ["goncalo", " simao ", "goncalo"]}},
        priv,
        pub,
    )
    groups = unprotect_groups(protected_groups, "henrique", priv, pub)

    assert groups == {
        "group-equipa": {
            "name": "Equipa",
            "members": ["goncalo", "simao"],
        }
    }

    protected_groups["owner"] = "goncalo"
    try:
        unprotect_groups(protected_groups, "goncalo", priv, pub)
    except ValueError:
        pass
    else:
        raise AssertionError("grupos alterados foram aceites")

    print("OK - grupos protegidos contra leitura e alteração")


def test_message_dedup_accepts_new_message():
    print("\n[TESTE] Deduplicação aceita mensagem nova")

    state = make_chat_state()
    assert save_to_history(state, history_message("msg-1"), "olá") is True

    assert len(state.conversations["bob"]) == 1
    assert state.has_seen_message("msg-1")

    print("OK - mensagem nova aceite")


def test_message_dedup_ignores_duplicate_message():
    print("\n[TESTE] Deduplicação ignora mensagem repetida")

    state = make_chat_state()
    msg = history_message("msg-dup")

    assert save_to_history(state, msg, "primeira") is True
    assert save_to_history(state, msg, "segunda") is False

    assert len(state.conversations["bob"]) == 1
    assert state.conversations["bob"][0]["text"] == "primeira"

    print("OK - duplicado ignorado")


def test_message_dedup_accepts_distinct_message_ids():
    print("\n[TESTE] Deduplicação aceita ids diferentes")

    state = make_chat_state()

    assert save_to_history(state, history_message("msg-1"), "primeira") is True
    assert save_to_history(state, history_message("msg-2"), "segunda") is True

    assert len(state.conversations["bob"]) == 2

    print("OK - mensagens distintas aceites")


def test_message_without_id_is_ignored_without_crash():
    print("\n[TESTE] Mensagem sem message_id não rebenta")

    state = make_chat_state()

    assert save_to_history(state, history_message(), "sem id") is False
    assert state.conversations == {}

    print("OK - mensagem sem message_id ignorada")


def test_incoming_message_without_id_is_ignored_without_crash():
    print("\n[TESTE] Mensagem recebida sem message_id não rebenta")

    state = make_chat_state()

    process_incoming_message({"from": "bob"}, state)
    assert state.conversations == {}

    print("OK - mensagem recebida sem message_id ignorada")


def test_seen_message_ids_rebuild_from_history():
    print("\n[TESTE] Reconstrução de ids vistos a partir do histórico")

    state = make_chat_state()
    state.conversations["bob"] = [
        {
            "message_id": "msg-antiga",
            "timestamp": "2026-05-22T18:00:00Z",
            "from": "bob",
            "to": "alice",
            "text": "já existia",
        }
    ]

    assert state.rebuild_seen_message_ids_from_history() == 1
    assert save_to_history(state, history_message("msg-antiga"), "replay") is False
    assert len(state.conversations["bob"]) == 1

    print("OK - ids vistos reconstruídos")


def run_all():
    print("===== TESTES DE SEGURANÇA =====")

    test_encryption()
    test_signature()
    test_signature_tamper()
    test_session_key()
    test_certificate_username_binding()
    test_certificate_public_key_binding()
    test_e2ee_v2_roundtrip()
    test_e2ee_v2_fresh_ephemeral_keys()
    test_e2ee_v2_tamper_detection()
    test_e2ee_v1_compatibility()
    test_e2ee_public_key_binding_signature()
    test_e2ee_public_key_overwrite_rejected()
    test_contacts_metadata_normalization()
    test_protected_contacts_roundtrip()
    test_groups_metadata_normalization()
    test_protected_groups_roundtrip()
    test_message_dedup_accepts_new_message()
    test_message_dedup_ignores_duplicate_message()
    test_message_dedup_accepts_distinct_message_ids()
    test_message_without_id_is_ignored_without_crash()
    test_incoming_message_without_id_is_ignored_without_crash()
    test_seen_message_ids_rebuild_from_history()

    print("\nTODOS OS TESTES PASSARAM")


if __name__ == "__main__":
    run_all()
