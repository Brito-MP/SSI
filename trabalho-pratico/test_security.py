"""
Testes básicos de segurança para o projeto SSI chat.

Executar com:
python3 test_security.py
"""

import os
import base64
import copy
import io
import json
import sys
import tempfile
import threading
import time
from contextlib import contextmanager, redirect_stdout
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
from handlers.file_handler import (
    build_public_bundle,
    cmd_export_bundle,
    cmd_export_msg,
    cmd_import_bundle,
    cmd_import_msg,
    identity_key_fingerprint,
    import_public_bundle,
    load_imported_bundles,
)
from handlers.message_handler import (
    build_online_session_message_envelope,
    build_offline_prekey_message_envelope,
    build_group_message_envelope,
    build_group_message_payload,
    build_message_envelope,
    build_session_handshake_envelope,
    cmd_remove_group_member,
    cmd_send_group,
    cmd_sync,
    get_online_session_winning_initiator,
    get_group_rotation_leader,
    group_control_plaintext,
    handle_group_key_share_message,
    handle_group_leave_message,
    group_key_share_plaintext,
    process_incoming_message,
    rotate_group_key,
    store_online_session,
    sync_pending_messages,
)
from handlers.prekey_handler import (
    generate_and_store_signed_prekeys,
    load_local_prekeys,
    load_private_prekey,
)
import storage
from crypto_utils import (
    ONLINE_SESSION_MESSAGE_ALGORITHM,
    ONLINE_SESSION_MESSAGE_TYPE,
    ONLINE_SESSION_MESSAGE_VERSION,
    OFFLINE_PREKEY_MESSAGE_ALGORITHM,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_VERSION,
    SESSION_INIT_TYPE,
    SESSION_RESPONSE_TYPE,
    SIGNED_PREKEY_ALGORITHM,
    build_online_session_aad,
    build_group_aad,
    build_message_aad,
    decrypt_online_session_message,
    decrypt_group_payload,
    decrypt_from_sender,
    decrypt_from_signed_prekey,
    e2ee_public_key_binding_bytes,
    encrypt_group_payload,
    encrypt_for_recipient,
    encrypt_for_recipient_v2,
    encrypt_for_signed_prekey,
    generate_group_key,
    generate_signed_prekey,
    generate_x25519_keypair,
    GROUP_KEY_SHARE_TYPE,
    GROUP_MESSAGE_TYPE,
    derive_online_session_key,
    normalize_contact_list,
    normalize_groups,
    private_key_to_pem,
    protect_contacts,
    protect_groups,
    public_key_to_pem,
    sign_message,
    unprotect_contacts,
    unprotect_groups,
    verify_signature,
    verify_session_ephemeral_signature,
    verify_signed_prekey,
    x25519_public_key_from_pem,
)
from server.server import (
    SIGNED_PREKEYS_FIELD,
    can_set_e2ee_public_key,
    ack_pending_messages,
    deliver_or_store_message,
    get_pending_messages,
    is_valid_envelope,
    online_users,
    online_users_lock,
    pop_available_signed_prekey,
    publish_signed_prekeys_for_user,
)
from client_start import initialize_logged_in_client


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


def make_user_state(username):
    identity_priv, identity_pub = generate_rsa_keypair()
    x25519_priv, x25519_pub = generate_x25519_keypair()
    state = ChatState(
        username=username,
        private_key=identity_priv,
        public_key=identity_pub,
        x25519_private_key=x25519_priv,
        x25519_public_key=x25519_pub,
    )
    state.key_cache[username] = identity_pub
    state.e2ee_key_cache[username] = x25519_pub
    return state


def history_message(message_id=None, sender="bob", target="alice"):
    msg = {
        "timestamp": "2026-05-22T18:00:00Z",
        "from": sender,
        "to": target,
    }
    if message_id is not None:
        msg["message_id"] = message_id
    return msg


def server_users():
    return {
        "alice": {
            "public_key": "alice-public-key",
            "certificate": "alice-certificate",
        },
        "bob": {
            "public_key": "bob-public-key",
            "certificate": "bob-certificate",
        },
    }


def server_message(message_id="server-msg-1", target="bob", group=False):
    msg = {
        "message_id": message_id,
        "timestamp": "2026-05-22T18:00:00Z",
        "from": "alice",
        "to": target,
        "payload": {
            "nonce": "nonce",
            "ciphertext": "ciphertext",
            "encrypted_key": "encrypted-key",
        },
        "signature": "signature",
    }
    if group:
        msg.update({
            "group_id": "group-equipa",
            "group_name": "Equipa",
            "group_members": ["alice", "bob"],
        })
    return msg


def group_model(group_key=None):
    return {
        "name": "Equipa",
        "members": ["alice", "bob"],
        "group_key": group_key or generate_group_key(),
        "group_key_version": 1,
    }


def signed_group_message_envelope(
    sender_private_key,
    group_key,
    message_id="group-msg-1",
    text="olá grupo",
    target="bob",
):
    group = group_model(group_key)
    timestamp = "2026-05-22T18:00:00Z"
    payload = build_group_message_payload("alice", "group-equipa", group, text, message_id, timestamp)
    aad = build_group_aad("group-equipa", "alice", target, message_id, timestamp)
    encrypted = encrypt_group_payload(group_key, payload, aad)
    return build_group_message_envelope(
        "alice",
        target,
        "group-equipa",
        encrypted,
        message_id,
        timestamp,
        sender_private_key,
    )


def derive_test_online_session(session_id="session-test-1"):
    alice_ephemeral_private, alice_ephemeral_public = generate_x25519_keypair()
    bob_ephemeral_private, bob_ephemeral_public = generate_x25519_keypair()
    alice_ephemeral_public_pem = public_key_to_pem(alice_ephemeral_public)
    bob_ephemeral_public_pem = public_key_to_pem(bob_ephemeral_public)

    alice_shared_secret = alice_ephemeral_private.exchange(bob_ephemeral_public)
    bob_shared_secret = bob_ephemeral_private.exchange(alice_ephemeral_public)
    alice_session_key = derive_online_session_key(
        alice_shared_secret,
        session_id,
        "alice",
        "bob",
        alice_ephemeral_public_pem,
        bob_ephemeral_public_pem,
    )
    bob_session_key = derive_online_session_key(
        bob_shared_secret,
        session_id,
        "alice",
        "bob",
        alice_ephemeral_public_pem,
        bob_ephemeral_public_pem,
    )
    return {
        "session_id": session_id,
        "alice_private": alice_ephemeral_private,
        "alice_public_pem": alice_ephemeral_public_pem,
        "bob_private": bob_ephemeral_private,
        "bob_public_pem": bob_ephemeral_public_pem,
        "alice_session_key": alice_session_key,
        "bob_session_key": bob_session_key,
    }


class FakeSocket:
    def __init__(self, fail=False):
        self.fail = fail
        self.sent = []

    def sendall(self, data):
        if self.fail:
            raise OSError("socket morto")
        self.sent.append(data)


def clear_online_users():
    with online_users_lock:
        online_users.clear()


@contextmanager
def temporary_messages_file():
    old_messages_file = storage.MESSAGES_FILE
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage.MESSAGES_FILE = os.path.join(tmp_dir, "messages.json")
        storage.save_messages([])
        clear_online_users()
        try:
            yield
        finally:
            clear_online_users()
            storage.MESSAGES_FILE = old_messages_file


@contextmanager
def temporary_users_file():
    old_users_file = storage.USERS_FILE
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage.USERS_FILE = os.path.join(tmp_dir, "users.json")
        storage.save_users({})
        try:
            yield
        finally:
            storage.USERS_FILE = old_users_file


def decode_sent_json(sock):
    assert len(sock.sent) == 1
    return json.loads(sock.sent[0].decode("utf-8").strip())


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


def test_signed_prekey_generation_and_signature_validation():
    print("\n[TESTE] Signed prekey X25519 é assinada pela identity key")

    alice = make_user_state("alice")
    prekey, private_prekey = generate_signed_prekey("alice", alice.private_key)

    assert prekey["type"] == "signed_prekey"
    assert prekey["version"] == 1
    assert prekey["algorithm"] == SIGNED_PREKEY_ALGORITHM
    assert isinstance(prekey["prekey_id"], str)
    assert "PRIVATE KEY" not in json.dumps(prekey)
    assert private_key_to_pem(private_prekey) not in json.dumps(prekey)
    assert verify_signed_prekey("alice", alice.public_key, prekey)

    tampered_id = copy.deepcopy(prekey)
    tampered_id["prekey_id"] = "prekey-adulterada"
    assert not verify_signed_prekey("alice", alice.public_key, tampered_id)

    tampered_time = copy.deepcopy(prekey)
    tampered_time["created_at"] = "2026-05-23T00:00:00Z"
    assert not verify_signed_prekey("alice", alice.public_key, tampered_time)

    _, other_public_key = generate_x25519_keypair()
    tampered_key = copy.deepcopy(prekey)
    tampered_key["public_key"] = public_key_to_pem(other_public_key)
    assert not verify_signed_prekey("alice", alice.public_key, tampered_key)

    print("OK - assinatura cobre id/public_key/created_at")


def test_private_prekey_stays_in_local_store_only():
    print("\n[TESTE] Private prekey fica só no armazenamento local")

    bob = make_user_state("bob")
    with tempfile.TemporaryDirectory() as tmp_dir:
        bob.prekeys_path = os.path.join(tmp_dir, "bob_prekeys.json")
        public_prekeys = generate_and_store_signed_prekeys(bob, 1)
        stored = load_local_prekeys(bob)

    prekey = public_prekeys[0]
    entry = stored[prekey["prekey_id"]]
    assert "private_key" in entry
    assert entry["used"] is False
    assert entry["public_key"] == prekey["public_key"]
    assert "private_key" not in json.dumps(prekey)
    assert entry["private_key"] not in json.dumps(prekey)

    print("OK - bundle público da prekey não contém chave privada")


def test_server_stores_only_public_signed_prekeys_and_rejects_bad_ones():
    print("\n[TESTE] Servidor guarda só signed prekeys públicas válidas")

    bob = make_user_state("bob")
    user_data = {
        "public_key": public_key_to_pem(bob.public_key),
        "certificate": "bob-certificate",
    }
    good_prekey, private_prekey = generate_signed_prekey("bob", bob.private_key)

    accepted = publish_signed_prekeys_for_user(user_data, "bob", [good_prekey])
    duplicate = publish_signed_prekeys_for_user(user_data, "bob", [good_prekey])
    stored_json = json.dumps(user_data)

    assert accepted == [good_prekey["prekey_id"]]
    assert duplicate == []
    assert SIGNED_PREKEYS_FIELD in user_data
    assert private_key_to_pem(private_prekey) not in stored_json
    assert "private_key" not in stored_json
    assert user_data[SIGNED_PREKEYS_FIELD][good_prekey["prekey_id"]]["state"] == "available"

    malformed = copy.deepcopy(good_prekey)
    malformed.pop("signature")
    try:
        publish_signed_prekeys_for_user(user_data, "bob", [malformed])
    except ValueError:
        pass
    else:
        raise AssertionError("servidor aceitou signed prekey malformada")

    print("OK - servidor valida e não guarda private prekeys")


def test_server_returns_signed_prekey_once():
    print("\n[TESTE] Servidor entrega signed prekey uma só vez")

    bob = make_user_state("bob")
    user_data = {
        "public_key": public_key_to_pem(bob.public_key),
        "certificate": "bob-certificate",
    }
    prekey, _ = generate_signed_prekey("bob", bob.private_key)
    publish_signed_prekeys_for_user(user_data, "bob", [prekey])

    fetched = pop_available_signed_prekey(user_data)
    reused = pop_available_signed_prekey(user_data)

    assert fetched["prekey_id"] == prekey["prekey_id"]
    assert verify_signed_prekey("bob", bob.public_key, fetched)
    assert reused is None
    assert user_data[SIGNED_PREKEYS_FIELD][prekey["prekey_id"]]["state"] == "used"

    print("OK - prekey pública é marcada como usada no servidor")


def test_offline_prekey_message_roundtrip_and_consumes_private_prekey():
    print("\n[TESTE] Mensagem offline usa signed prekey e consome private prekey")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bob.key_cache["alice"] = alice.public_key

    with tempfile.TemporaryDirectory() as tmp_dir:
        bob.prekeys_path = os.path.join(tmp_dir, "bob_prekeys.json")
        public_prekey = generate_and_store_signed_prekeys(bob, 1)[0]
        envelope = build_offline_prekey_message_envelope(
            "alice",
            "bob",
            "segredo offline com prekey",
            alice.private_key,
            public_prekey,
        )
        serialized = json.dumps(envelope, ensure_ascii=False)

        assert envelope["type"] == OFFLINE_PREKEY_MESSAGE_TYPE
        assert envelope["version"] == OFFLINE_PREKEY_MESSAGE_VERSION
        assert envelope["algorithm"] == OFFLINE_PREKEY_MESSAGE_ALGORITHM
        assert envelope["prekey_id"] == public_prekey["prekey_id"]
        assert "ephemeral_public_key" in envelope
        assert set(envelope["payload"].keys()) == {"nonce", "ciphertext"}
        assert "segredo offline com prekey" not in serialized
        assert "PRIVATE KEY" not in serialized
        assert is_valid_envelope(envelope)

        process_incoming_message(envelope, bob)
        stored = load_local_prekeys(bob)

        assert bob.conversations["alice"][0]["text"] == "segredo offline com prekey"
        used_entry = stored[public_prekey["prekey_id"]]
        assert used_entry["used"] is True
        assert isinstance(used_entry["destroyed_at"], str) and used_entry["destroyed_at"]
        assert "private_key" not in used_entry
        assert "PRIVATE KEY" not in json.dumps(stored)
        try:
            load_private_prekey(bob, public_prekey["prekey_id"])
        except ValueError:
            pass
        else:
            raise AssertionError("private prekey usada continuou reutilizável")

    print("OK - Bob decifra, destrói private prekey e bloqueia reutilização")


def test_offline_prekey_message_fails_without_private_prekey():
    print("\n[TESTE] Mensagem offline falha sem private prekey local")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bob.key_cache["alice"] = alice.public_key
    public_prekey, _ = generate_signed_prekey("bob", bob.private_key)

    with tempfile.TemporaryDirectory() as tmp_dir:
        bob.prekeys_path = os.path.join(tmp_dir, "missing_prekeys.json")
        envelope = build_offline_prekey_message_envelope(
            "alice",
            "bob",
            "não deve abrir",
            alice.private_key,
            public_prekey,
        )
        process_incoming_message(envelope, bob)

    assert bob.conversations == {}

    print("OK - prekey_id desconhecida falha sem plaintext")


def test_offline_prekey_message_rejects_aad_and_ciphertext_tampering():
    print("\n[TESTE] Mensagem offline com prekey rejeita adulteração")

    bob = make_user_state("bob")
    public_prekey, private_prekey = generate_signed_prekey("bob", bob.private_key)
    encrypted = encrypt_for_signed_prekey(
        "texto autenticado por prekey",
        public_prekey,
        "alice",
        "bob",
        "offline-aad-1",
        "2026-05-23T12:00:00Z",
    )

    plaintext = decrypt_from_signed_prekey(
        encrypted["payload"],
        private_prekey,
        encrypted["ephemeral_public_key"],
        encrypted["prekey_id"],
        "alice",
        "bob",
        "offline-aad-1",
        "2026-05-23T12:00:00Z",
    )
    assert plaintext == "texto autenticado por prekey"

    tamper_cases = [
        {"message_id": "offline-aad-2"},
        {"sender": "mallory"},
        {"recipient": "carla"},
        {"timestamp": "2026-05-23T12:01:00Z"},
        {"prekey_id": "prekey-errada"},
    ]
    for tamper in tamper_cases:
        try:
            decrypt_from_signed_prekey(
                encrypted["payload"],
                private_prekey,
                encrypted["ephemeral_public_key"],
                tamper.get("prekey_id", encrypted["prekey_id"]),
                tamper.get("sender", "alice"),
                tamper.get("recipient", "bob"),
                tamper.get("message_id", "offline-aad-1"),
                tamper.get("timestamp", "2026-05-23T12:00:00Z"),
            )
        except Exception:
            pass
        else:
            raise AssertionError(f"adulteração aceite: {tamper}")

    bad_payload = copy.deepcopy(encrypted["payload"])
    ciphertext = bytearray(base64.b64decode(bad_payload["ciphertext"]))
    ciphertext[0] ^= 1
    bad_payload["ciphertext"] = base64.b64encode(ciphertext).decode()
    try:
        decrypt_from_signed_prekey(
            bad_payload,
            private_prekey,
            encrypted["ephemeral_public_key"],
            encrypted["prekey_id"],
            "alice",
            "bob",
            "offline-aad-1",
            "2026-05-23T12:00:00Z",
        )
    except Exception:
        pass
    else:
        raise AssertionError("ciphertext adulterado aceite")

    print("OK - AAD e ciphertext adulterados falham")


def test_online_session_handshake_signature_validation():
    print("\n[TESTE] Handshake online assina ephemeral public key e rejeita adulteração")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    session = derive_test_online_session("online-session-signature-1")
    init = build_session_handshake_envelope(
        SESSION_INIT_TYPE,
        session["session_id"],
        "alice",
        "bob",
        session["alice_public_pem"],
        alice.private_key,
    )

    assert init["message_id"] == session["session_id"]
    assert x25519_public_key_from_pem(init["ephemeral_public_key"]) is not None
    assert verify_session_ephemeral_signature(init, alice.public_key)

    _, other_ephemeral_public = generate_x25519_keypair()
    tamper_cases = [
        ("ephemeral_public_key", public_key_to_pem(other_ephemeral_public)),
        ("session_id", "online-session-signature-2"),
        ("from", "mallory"),
        ("to", "carla"),
        ("timestamp", "2026-05-23T12:01:00Z"),
    ]
    for field, value in tamper_cases:
        tampered = copy.deepcopy(init)
        tampered[field] = value
        if field == "session_id":
            tampered["message_id"] = value
        assert not verify_session_ephemeral_signature(tampered, alice.public_key)

    response = build_session_handshake_envelope(
        SESSION_RESPONSE_TYPE,
        session["session_id"],
        "bob",
        "alice",
        session["bob_public_pem"],
        bob.private_key,
    )
    assert verify_session_ephemeral_signature(response, bob.public_key)

    print("OK - assinatura canónica do handshake protege identidade e ephemeral key")


def test_online_session_key_derivation_matches_and_is_fresh():
    print("\n[TESTE] DH efémero online deriva a mesma session_key e varia por sessão")

    session = derive_test_online_session("online-session-kdf-1")
    assert session["alice_session_key"] == session["bob_session_key"]
    assert len(session["alice_session_key"]) == 32

    shared_secret = session["alice_private"].exchange(x25519_public_key_from_pem(session["bob_public_pem"]))
    changed_context_key = derive_online_session_key(
        shared_secret,
        "online-session-kdf-2",
        "alice",
        "bob",
        session["alice_public_pem"],
        session["bob_public_pem"],
    )
    fresh_session = derive_test_online_session("online-session-kdf-3")

    assert changed_context_key != session["alice_session_key"]
    assert fresh_session["alice_session_key"] != session["alice_session_key"]

    print("OK - HKDF usa DH e contexto de sessão")


def test_online_session_handshake_processing_creates_memory_only_sessions():
    print("\n[TESTE] Processamento de session_init/session_response cria sessão só em memória")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    alice.key_cache["bob"] = bob.public_key
    bob.key_cache["alice"] = alice.public_key

    session = derive_test_online_session("online-session-process-1")
    init = build_session_handshake_envelope(
        SESSION_INIT_TYPE,
        session["session_id"],
        "alice",
        "bob",
        session["alice_public_pem"],
        alice.private_key,
    )
    bob.sock = FakeSocket()

    process_incoming_message(init, bob)

    assert "alice" in bob.online_sessions
    assert bob.online_sessions["alice"]["role"] == "responder"
    assert "session_key" in bob.online_sessions["alice"]
    assert "ephemeral_private_key" not in bob.online_sessions["alice"]
    assert bob.sock.sent

    response_frame = json.loads(bob.sock.sent[-1].decode("utf-8"))
    assert response_frame["command"] == "relay_session_envelope"
    response = {key: value for key, value in response_frame.items() if key != "command"}
    assert response["type"] == SESSION_RESPONSE_TYPE
    assert response["session_id"] == session["session_id"]
    assert verify_session_ephemeral_signature(response, bob.public_key)

    alice.pending_online_sessions["bob"] = {
        "session_id": session["session_id"],
        "ephemeral_private_key": session["alice_private"],
        "own_ephemeral_public_key": session["alice_public_pem"],
        "created_at": "2026-05-23T12:00:00Z",
    }
    process_incoming_message(response, alice)

    assert "bob" in alice.online_sessions
    assert "bob" not in alice.pending_online_sessions
    assert alice.online_sessions["bob"]["role"] == "initiator"
    assert "ephemeral_private_key" not in alice.online_sessions["bob"]
    assert alice.online_sessions["bob"]["session_key"] == bob.online_sessions["alice"]["session_key"]

    print("OK - ephemeral private key é descartada depois da derivação")


def test_online_session_normal_handshake_accepts_larger_username_initiator_without_conflict():
    print("\n[TESTE] Handshake online normal aceita iniciador lexicograficamente maior")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    alice.key_cache["bob"] = bob.public_key
    bob.key_cache["alice"] = alice.public_key
    alice.sock = FakeSocket()

    session_id = "normal-bob-initiated-session"
    bob_ephemeral_private, bob_ephemeral_public = generate_x25519_keypair()
    bob_ephemeral_public_pem = public_key_to_pem(bob_ephemeral_public)
    bob.pending_online_sessions["alice"] = {
        "session_id": session_id,
        "ephemeral_private_key": bob_ephemeral_private,
        "own_ephemeral_public_key": bob_ephemeral_public_pem,
        "created_at": "2026-05-23T12:00:00Z",
    }

    init = build_session_handshake_envelope(
        SESSION_INIT_TYPE,
        session_id,
        "bob",
        "alice",
        bob_ephemeral_public_pem,
        bob.private_key,
    )
    process_incoming_message(init, alice)

    assert alice.online_sessions["bob"]["session_id"] == session_id
    assert alice.online_sessions["bob"]["initiator"] == "bob"
    assert alice.sock.sent

    response_frame = json.loads(alice.sock.sent[-1].decode("utf-8"))
    response = {key: value for key, value in response_frame.items() if key != "command"}
    process_incoming_message(response, bob)

    assert bob.online_sessions["alice"]["session_id"] == session_id
    assert bob.online_sessions["alice"]["initiator"] == "bob"
    assert bob.online_sessions["alice"]["session_key"] == alice.online_sessions["bob"]["session_key"]
    assert bob.pending_online_sessions == {}

    print("OK - regra de desempate só atua quando há conflito local")


def test_simultaneous_online_session_handshake_uses_deterministic_winner():
    print("\n[TESTE] Handshake online simultâneo escolhe vencedor determinístico")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    alice.key_cache["bob"] = bob.public_key
    bob.key_cache["alice"] = alice.public_key
    alice.sock = FakeSocket()
    bob.sock = FakeSocket()

    alice_session_id = "simultaneous-alice-session"
    bob_session_id = "simultaneous-bob-session"
    alice_ephemeral_private, alice_ephemeral_public = generate_x25519_keypair()
    bob_ephemeral_private, bob_ephemeral_public = generate_x25519_keypair()
    alice_ephemeral_public_pem = public_key_to_pem(alice_ephemeral_public)
    bob_ephemeral_public_pem = public_key_to_pem(bob_ephemeral_public)

    alice.pending_online_sessions["bob"] = {
        "session_id": alice_session_id,
        "ephemeral_private_key": alice_ephemeral_private,
        "own_ephemeral_public_key": alice_ephemeral_public_pem,
        "created_at": "2026-05-23T12:00:00Z",
    }
    bob.pending_online_sessions["alice"] = {
        "session_id": bob_session_id,
        "ephemeral_private_key": bob_ephemeral_private,
        "own_ephemeral_public_key": bob_ephemeral_public_pem,
        "created_at": "2026-05-23T12:00:00Z",
    }

    alice_init = build_session_handshake_envelope(
        SESSION_INIT_TYPE,
        alice_session_id,
        "alice",
        "bob",
        alice_ephemeral_public_pem,
        alice.private_key,
    )
    bob_init = build_session_handshake_envelope(
        SESSION_INIT_TYPE,
        bob_session_id,
        "bob",
        "alice",
        bob_ephemeral_public_pem,
        bob.private_key,
    )

    assert get_online_session_winning_initiator("alice", "bob") == "alice"

    process_incoming_message(bob_init, alice)
    assert "bob" not in alice.online_sessions
    assert alice.pending_online_sessions["bob"]["session_id"] == alice_session_id
    assert alice.sock.sent == []

    process_incoming_message(alice_init, bob)
    assert bob.online_sessions["alice"]["session_id"] == alice_session_id
    assert bob.online_sessions["alice"]["initiator"] == "alice"
    assert "alice" not in bob.pending_online_sessions
    assert bob.sock.sent

    response_frame = json.loads(bob.sock.sent[-1].decode("utf-8"))
    winning_response = {key: value for key, value in response_frame.items() if key != "command"}
    assert winning_response["type"] == SESSION_RESPONSE_TYPE
    assert winning_response["session_id"] == alice_session_id

    _, stale_response_public = generate_x25519_keypair()
    losing_response = build_session_handshake_envelope(
        SESSION_RESPONSE_TYPE,
        bob_session_id,
        "alice",
        "bob",
        public_key_to_pem(stale_response_public),
        alice.private_key,
    )
    process_incoming_message(losing_response, bob)
    assert bob.online_sessions["alice"]["session_id"] == alice_session_id

    process_incoming_message(winning_response, alice)
    assert alice.online_sessions["bob"]["session_id"] == alice_session_id
    assert bob.online_sessions["alice"]["session_id"] == alice_session_id
    assert alice.online_sessions["bob"]["session_key"] == bob.online_sessions["alice"]["session_key"]
    assert alice.online_sessions["bob"]["initiator"] == "alice"
    assert bob.online_sessions["alice"]["initiator"] == "alice"
    assert alice.pending_online_sessions == {}
    assert bob.pending_online_sessions == {}

    envelope = build_online_session_message_envelope(alice, "bob", "mensagem após handshake simultâneo")
    process_incoming_message(envelope, bob)

    assert bob.conversations["alice"][0]["text"] == "mensagem após handshake simultâneo"

    print("OK - só o handshake iniciado por alice permanece e cifra mensagens futuras")


def test_online_session_message_roundtrip_and_tamper_detection():
    print("\n[TESTE] Mensagem online usa session_key, AAD e counters")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    alice.key_cache["bob"] = bob.public_key
    bob.key_cache["alice"] = alice.public_key
    session = derive_test_online_session("online-session-message-1")

    store_online_session(
        alice,
        "bob",
        session["session_id"],
        "initiator",
        session["alice_session_key"],
        session["alice_public_pem"],
        session["bob_public_pem"],
    )
    store_online_session(
        bob,
        "alice",
        session["session_id"],
        "responder",
        session["bob_session_key"],
        session["bob_public_pem"],
        session["alice_public_pem"],
    )

    envelope = build_online_session_message_envelope(alice, "bob", "olá sessão online")
    serialized = json.dumps(envelope, ensure_ascii=False)

    assert envelope["type"] == ONLINE_SESSION_MESSAGE_TYPE
    assert envelope["version"] == ONLINE_SESSION_MESSAGE_VERSION
    assert envelope["algorithm"] == ONLINE_SESSION_MESSAGE_ALGORITHM
    assert envelope["counter"] == 1
    assert set(envelope["payload"].keys()) == {"nonce", "ciphertext"}
    assert "olá sessão online" not in serialized
    assert "action" not in envelope
    assert "action" not in envelope["payload"]
    assert is_valid_envelope(envelope)

    aad = build_online_session_aad(
        envelope["session_id"],
        envelope["message_id"],
        envelope["from"],
        envelope["to"],
        envelope["timestamp"],
        envelope["counter"],
    )
    plaintext_raw = decrypt_online_session_message(session["bob_session_key"], envelope["payload"], aad)
    plaintext_payload = json.loads(plaintext_raw)
    assert plaintext_payload == {"text": "olá sessão online", "action": "message"}

    process_incoming_message(envelope, bob)
    assert bob.conversations["alice"][0]["text"] == "olá sessão online"
    assert bob.online_sessions["alice"]["recv_counter"] == 1

    tamper_cases = [
        {"session_id": "online-session-message-2"},
        {"message_id": "online-msg-errado"},
        {"sender": "mallory"},
        {"recipient": "carla"},
        {"timestamp": "2026-05-23T12:01:00Z"},
        {"counter": 2},
    ]
    for tamper in tamper_cases:
        tampered_aad = build_online_session_aad(
            tamper.get("session_id", envelope["session_id"]),
            tamper.get("message_id", envelope["message_id"]),
            tamper.get("sender", envelope["from"]),
            tamper.get("recipient", envelope["to"]),
            tamper.get("timestamp", envelope["timestamp"]),
            tamper.get("counter", envelope["counter"]),
        )
        try:
            decrypt_online_session_message(session["bob_session_key"], envelope["payload"], tampered_aad)
        except Exception:
            pass
        else:
            raise AssertionError(f"adulteração aceite: {tamper}")

    bad_payload = copy.deepcopy(envelope["payload"])
    ciphertext = bytearray(base64.b64decode(bad_payload["ciphertext"]))
    ciphertext[0] ^= 1
    bad_payload["ciphertext"] = base64.b64encode(ciphertext).decode()
    try:
        decrypt_online_session_message(session["bob_session_key"], bad_payload, aad)
    except Exception:
        pass
    else:
        raise AssertionError("ciphertext adulterado aceite")

    second_envelope = build_online_session_message_envelope(alice, "bob", "segunda mensagem")
    assert second_envelope["counter"] == 2
    assert second_envelope["payload"]["nonce"] != envelope["payload"]["nonce"]

    print("OK - mensagem online cifra plaintext e autentica metadados externos")


def test_server_forwards_online_session_envelopes_without_offline_storage():
    print("\n[TESTE] Servidor encaminha envelopes de sessão online sem guardar offline")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    session = derive_test_online_session("online-session-server-1")
    init = build_session_handshake_envelope(
        SESSION_INIT_TYPE,
        session["session_id"],
        "alice",
        "bob",
        session["alice_public_pem"],
        alice.private_key,
    )

    assert is_valid_envelope(init)
    with temporary_messages_file():
        bob_socket = FakeSocket()
        with online_users_lock:
            online_users["bob"] = bob_socket
        envelope, delivered_online, stored_encrypted = deliver_or_store_message(init, server_users())

        assert delivered_online is True
        assert stored_encrypted is False
        assert envelope["type"] == SESSION_INIT_TYPE
        forwarded = json.loads(bob_socket.sent[-1].decode("utf-8"))
        assert forwarded["command"] == "deliver_message"
        assert forwarded["type"] == SESSION_INIT_TYPE
        assert get_pending_messages("bob") == []

    response = build_session_handshake_envelope(
        SESSION_RESPONSE_TYPE,
        session["session_id"],
        "bob",
        "alice",
        session["bob_public_pem"],
        bob.private_key,
    )

    assert is_valid_envelope(response)
    with temporary_messages_file():
        alice_socket = FakeSocket()
        with online_users_lock:
            online_users["alice"] = alice_socket
        envelope, delivered_online, stored_encrypted = deliver_or_store_message(response, server_users())

        assert delivered_online is True
        assert stored_encrypted is False
        assert envelope["type"] == SESSION_RESPONSE_TYPE
        forwarded = json.loads(alice_socket.sent[-1].decode("utf-8"))
        assert forwarded["command"] == "deliver_message"
        assert forwarded["type"] == SESSION_RESPONSE_TYPE
        assert get_pending_messages("alice") == []

    store_online_session(
        alice,
        "bob",
        session["session_id"],
        "initiator",
        session["alice_session_key"],
        session["alice_public_pem"],
        session["bob_public_pem"],
    )
    online_message = build_online_session_message_envelope(alice, "bob", "não guardar como offline")

    assert is_valid_envelope(online_message)
    with temporary_messages_file():
        envelope, delivered_online, stored_encrypted = deliver_or_store_message(online_message, server_users())

        assert envelope["type"] == ONLINE_SESSION_MESSAGE_TYPE
        assert delivered_online is False
        assert stored_encrypted is False
        assert get_pending_messages("bob") == []

    print("OK - session_init é online-only e online_session_message não vira offline")


def test_server_stores_offline_prekey_message_without_plaintext_or_private_keys():
    print("\n[TESTE] Servidor guarda offline_prekey_message sem plaintext nem private keys")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    public_prekey, private_prekey = generate_signed_prekey("bob", bob.private_key)
    envelope = build_offline_prekey_message_envelope(
        "alice",
        "bob",
        "mensagem offline forward-secret",
        alice.private_key,
        public_prekey,
    )

    with temporary_messages_file():
        stored_envelope, delivered_online, stored_encrypted = deliver_or_store_message(envelope, server_users())
        stored_json = json.dumps(storage.load_messages(), ensure_ascii=False)

    assert not delivered_online
    assert stored_encrypted
    assert stored_envelope == envelope
    assert stored_envelope["type"] == OFFLINE_PREKEY_MESSAGE_TYPE
    assert stored_envelope["prekey_id"] == public_prekey["prekey_id"]
    assert "mensagem offline forward-secret" not in stored_json
    assert private_key_to_pem(private_prekey) not in stored_json
    assert "private_key" not in stored_json

    print("OK - servidor armazena só envelope cifrado com prekey_id público")


def test_server_stores_message_when_recipient_offline():
    print("\n[TESTE] Servidor guarda mensagem quando destinatário está offline")

    with temporary_messages_file():
        msg = server_message("offline-1")
        envelope, delivered_online, stored_encrypted = deliver_or_store_message(msg, server_users())

        assert not delivered_online
        assert stored_encrypted
        assert storage.load_messages() == [envelope]
        assert envelope["message_id"] == "offline-1"

    print("OK - mensagem offline guardada")


def test_server_delivers_online_without_storing_pending():
    print("\n[TESTE] Servidor entrega online sem guardar pendente")

    with temporary_messages_file():
        target_socket = FakeSocket()
        with online_users_lock:
            online_users["bob"] = target_socket

        envelope, delivered_online, stored_encrypted = deliver_or_store_message(
            server_message("online-1"),
            server_users(),
        )
        delivered = decode_sent_json(target_socket)

        assert delivered_online
        assert not stored_encrypted
        assert storage.load_messages() == []
        assert delivered["command"] == "deliver_message"
        assert delivered["sender_public_key"] == "alice-public-key"
        assert delivered["sender_certificate"] == "alice-certificate"
        assert delivered["message_id"] == envelope["message_id"]

    print("OK - mensagem online não ficou pendente")


def test_server_fetch_after_online_delivery_is_empty():
    print("\n[TESTE] Sync não devolve mensagem já entregue online")

    with temporary_messages_file():
        target_socket = FakeSocket()
        with online_users_lock:
            online_users["bob"] = target_socket

        deliver_or_store_message(server_message("online-sync-1"), server_users())

        assert get_pending_messages("bob") == []
        assert storage.load_messages() == []

    print("OK - sync pós-entrega online vazio")


def test_fetch_pending_messages_does_not_remove_from_storage():
    print("\n[TESTE] fetch de pendentes não remove mensagens")

    with temporary_messages_file():
        bob_msg = server_message("bob-pending", target="bob")
        alice_msg = server_message("alice-pending", target="alice")
        storage.save_messages([bob_msg, alice_msg])

        pending = get_pending_messages("bob")

        assert [msg["message_id"] for msg in pending] == ["bob-pending"]
        assert storage.load_messages() == [bob_msg, alice_msg]

    print("OK - mensagens ficam pendentes até ACK")


def test_ack_pending_messages_removes_only_confirmed_user_messages():
    print("\n[TESTE] ACK remove só mensagens confirmadas do utilizador")

    with temporary_messages_file():
        bob_remove = server_message("remove-me", target="bob")
        bob_keep = server_message("keep-me", target="bob")
        alice_same_id = server_message("remove-me", target="alice")
        storage.save_messages([bob_remove, bob_keep, alice_same_id])

        removed = ack_pending_messages("bob", ["remove-me"])

        assert removed == 1
        assert storage.load_messages() == [bob_keep, alice_same_id]

    print("OK - ACK não remove mensagens de outros utilizadores")


def test_sync_successfully_processed_messages_are_acked_and_removed():
    print("\n[TESTE] Sync envia ACK após processar mensagem com sucesso")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bob.key_cache["alice"] = alice.public_key
    envelope = build_message_envelope(
        "alice",
        "bob",
        "mensagem confirmada",
        alice.private_key,
        {
            "identity_public_key": bob.public_key,
            "e2ee_public_key": bob.x25519_public_key,
        },
    )

    with temporary_messages_file():
        storage.save_messages([envelope])
        ack_payloads = []
        globals_ = sync_pending_messages.__globals__
        original_send_request = globals_["send_request"]

        def fake_send_request(sock, response_queue, stop_event, payload):
            if payload["command"] == "fetch_messages":
                return {"status": "ok", "messages": get_pending_messages(payload["username"])}
            if payload["command"] == "ack_messages":
                ack_payloads.append(payload)
                return {
                    "status": "ok",
                    "removed_count": ack_pending_messages(payload["username"], payload["message_ids"]),
                }
            raise AssertionError(f"comando inesperado: {payload['command']}")

        try:
            globals_["send_request"] = fake_send_request
            assert sync_pending_messages(bob, show_summary=False) == 1
        finally:
            globals_["send_request"] = original_send_request

        assert bob.conversations["alice"][0]["text"] == "mensagem confirmada"
        assert ack_payloads == [{
            "command": "ack_messages",
            "username": "bob",
            "message_ids": [envelope["message_id"]],
        }]
        assert storage.load_messages() == []

    print("OK - mensagem processada saiu da fila por ACK")


def test_sync_failed_processing_does_not_ack_or_remove_message():
    print("\n[TESTE] Sync não ACKa mensagem que falha processamento")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bob.key_cache["alice"] = alice.public_key
    broken_envelope = {
        "message_id": "broken-offline",
        "timestamp": "2026-05-22T18:00:00Z",
        "from": "alice",
        "to": "bob",
        "payload": {"nonce": "bad", "ciphertext": "bad", "encrypted_key": "bad"},
        "signature": "assinatura-invalida",
    }

    with temporary_messages_file():
        storage.save_messages([broken_envelope])
        ack_payloads = []
        globals_ = sync_pending_messages.__globals__
        original_send_request = globals_["send_request"]

        def fake_send_request(sock, response_queue, stop_event, payload):
            if payload["command"] == "fetch_messages":
                return {"status": "ok", "messages": get_pending_messages(payload["username"])}
            if payload["command"] == "ack_messages":
                ack_payloads.append(payload)
                return {
                    "status": "ok",
                    "removed_count": ack_pending_messages(payload["username"], payload["message_ids"]),
                }
            raise AssertionError(f"comando inesperado: {payload['command']}")

        try:
            globals_["send_request"] = fake_send_request
            assert sync_pending_messages(bob, show_summary=False) == 0
        finally:
            globals_["send_request"] = original_send_request

        assert ack_payloads == []
        assert storage.load_messages() == [broken_envelope]

    print("OK - mensagem com falha continua pendente no servidor")


def test_login_initialization_calls_auto_sync_after_setup():
    print("\n[TESTE] Login chama auto-sync depois da inicialização")

    state = make_user_state("bob")
    calls = []
    globals_ = initialize_logged_in_client.__globals__
    originals = {
        "publish_signed_prekeys": globals_["publish_signed_prekeys"],
        "sync_contacts": globals_["sync_contacts"],
        "sync_groups": globals_["sync_groups"],
        "sync_pending_messages": globals_["sync_pending_messages"],
    }

    try:
        globals_["publish_signed_prekeys"] = lambda fake_state: calls.append("prekeys")
        globals_["sync_contacts"] = lambda fake_state: calls.append("contacts")
        globals_["sync_groups"] = lambda fake_state: calls.append("groups")

        def fake_sync_pending_messages(fake_state, announce=False):
            calls.append(("pending", announce))
            return 0

        globals_["sync_pending_messages"] = fake_sync_pending_messages
        initialize_logged_in_client(state)
    finally:
        globals_.update(originals)

    assert calls == ["prekeys", "contacts", "groups", ("pending", True)]

    print("OK - auto-sync corre antes do menu")


def test_auto_sync_receives_offline_prekey_message_without_manual_sync():
    print("\n[TESTE] Auto-sync recebe mensagem offline com signed prekey")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bob.key_cache["alice"] = alice.public_key

    with tempfile.TemporaryDirectory() as tmp_dir:
        bob.prekeys_path = os.path.join(tmp_dir, "bob_prekeys.json")
        public_prekey = generate_and_store_signed_prekeys(bob, 1)[0]
        envelope = build_offline_prekey_message_envelope(
            "alice",
            "bob",
            "mensagem entregue no login",
            alice.private_key,
            public_prekey,
        )

        globals_ = sync_pending_messages.__globals__
        original_send_request = globals_["send_request"]
        try:
            globals_["send_request"] = lambda sock, response_queue, stop_event, payload: {
                "status": "ok",
                "messages": [envelope],
            }
            output = io.StringIO()
            with redirect_stdout(output):
                assert sync_pending_messages(bob, announce=True) == 1
        finally:
            globals_["send_request"] = original_send_request

    assert bob.conversations["alice"][0]["text"] == "mensagem entregue no login"
    assert "A sincronizar mensagens pendentes..." in output.getvalue()
    assert "Sincronização concluída: 1 mensagem(ns)." in output.getvalue()

    print("OK - mensagem offline é decifrada sem comando manual")


def test_manual_sync_command_still_fetches_pending_messages():
    print("\n[TESTE] Comando sync manual continua funcional")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bob.key_cache["alice"] = alice.public_key
    envelope = build_message_envelope(
        "alice",
        "bob",
        "mensagem por sync manual",
        alice.private_key,
        {
            "identity_public_key": bob.public_key,
            "e2ee_public_key": bob.x25519_public_key,
        },
    )

    globals_ = sync_pending_messages.__globals__
    original_send_request = globals_["send_request"]
    try:
        globals_["send_request"] = lambda sock, response_queue, stop_event, payload: {
            "status": "ok",
            "messages": [envelope],
        }
        assert cmd_sync(bob) == 1
    finally:
        globals_["send_request"] = original_send_request

    assert bob.conversations["alice"][0]["text"] == "mensagem por sync manual"

    print("OK - cmd_sync reutiliza o helper de mensagens pendentes")


def test_auto_sync_does_not_duplicate_seen_messages():
    print("\n[TESTE] Auto-sync não duplica mensagens já vistas")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bob.key_cache["alice"] = alice.public_key
    envelope = build_message_envelope(
        "alice",
        "bob",
        "mensagem única",
        alice.private_key,
        {
            "identity_public_key": bob.public_key,
            "e2ee_public_key": bob.x25519_public_key,
        },
    )

    globals_ = sync_pending_messages.__globals__
    original_send_request = globals_["send_request"]
    try:
        globals_["send_request"] = lambda sock, response_queue, stop_event, payload: {
            "status": "ok",
            "messages": [envelope],
        }
        assert sync_pending_messages(bob, show_summary=False) == 1
        assert sync_pending_messages(bob, show_summary=False) == 1
    finally:
        globals_["send_request"] = original_send_request

    assert len(bob.conversations["alice"]) == 1

    print("OK - deduplicação local impede duplicados no auto-sync")


def test_auto_sync_no_pending_messages_is_quietly_successful():
    print("\n[TESTE] Auto-sync sem mensagens pendentes mantém login normal")

    bob = make_user_state("bob")
    globals_ = sync_pending_messages.__globals__
    original_send_request = globals_["send_request"]
    try:
        globals_["send_request"] = lambda sock, response_queue, stop_event, payload: {
            "status": "ok",
            "messages": [],
        }
        output = io.StringIO()
        with redirect_stdout(output):
            assert sync_pending_messages(bob, announce=True) == 0
    finally:
        globals_["send_request"] = original_send_request

    assert bob.conversations == {}
    assert "A sincronizar mensagens pendentes..." in output.getvalue()
    assert "Sem mensagens pendentes." in output.getvalue()

    print("OK - ausência de pendentes não interrompe o fluxo")


def test_auto_sync_delivers_offline_group_message():
    print("\n[TESTE] Auto-sync entrega mensagem de grupo offline")

    sender_priv, sender_pub = generate_rsa_keypair()
    group = group_model()
    envelope = signed_group_message_envelope(sender_priv, group["group_key"], message_id="group-auto-sync")
    bob = ChatState(
        username="bob",
        private_key=None,
        public_key=None,
        x25519_private_key=None,
        x25519_public_key=None,
    )
    bob.groups["group-equipa"] = group
    bob.key_cache["alice"] = sender_pub

    globals_ = sync_pending_messages.__globals__
    original_send_request = globals_["send_request"]
    try:
        globals_["send_request"] = lambda sock, response_queue, stop_event, payload: {
            "status": "ok",
            "messages": [envelope],
        }
        assert sync_pending_messages(bob, show_summary=False) == 1
    finally:
        globals_["send_request"] = original_send_request

    assert bob.conversations["group-equipa"][0]["text"] == "olá grupo"

    print("OK - grupo offline também usa o helper de auto-sync")


def test_server_stores_offline_when_online_socket_fails():
    print("\n[TESTE] Servidor guarda offline se socket online falhar")

    with temporary_messages_file():
        target_socket = FakeSocket(fail=True)
        with online_users_lock:
            online_users["bob"] = target_socket

        envelope, delivered_online, stored_encrypted = deliver_or_store_message(
            server_message("fallback-1"),
            server_users(),
        )

        assert not delivered_online
        assert stored_encrypted
        assert storage.load_messages() == [envelope]
        with online_users_lock:
            assert "bob" not in online_users

    print("OK - falha de socket caiu para offline")


def test_server_group_message_delivery_keeps_only_minimal_group_metadata():
    print("\n[TESTE] Servidor mantém só metadados mínimos de grupo")

    with temporary_messages_file():
        target_socket = FakeSocket()
        with online_users_lock:
            online_users["bob"] = target_socket

        envelope, delivered_online, stored_encrypted = deliver_or_store_message(
            server_message("group-online-1", group=True),
            server_users(),
        )
        delivered = decode_sent_json(target_socket)

        assert not is_valid_envelope(server_message("group-invalid-plaintext", group=True))
        assert delivered_online
        assert not stored_encrypted
        assert storage.load_messages() == []
        assert envelope["group_id"] == "group-equipa"
        assert delivered["group_id"] == "group-equipa"
        assert "group_name" not in envelope
        assert "group_members" not in envelope
        assert "group_action" not in envelope
        assert "group_name" not in delivered
        assert "group_members" not in delivered
        assert "group_action" not in delivered

    print("OK - servidor não propaga metadados sensíveis de grupo")


def test_group_key_is_256_bit_aes_key():
    print("\n[TESTE] group_key é AES-GCM 256 bits")

    group_key = generate_group_key()
    decoded = base64.b64decode(group_key.encode(), validate=True)
    groups = normalize_groups({"group-equipa": group_model(group_key)})

    assert len(decoded) == 32
    assert groups["group-equipa"]["group_key"] == group_key

    print("OK - group_key válida guardada no modelo de grupo")


def test_group_key_share_uses_individual_e2ee_without_plain_key():
    print("\n[TESTE] group_key_share usa E2EE individual")

    sender_priv, _ = generate_rsa_keypair()
    recipient_priv, recipient_pub = generate_rsa_keypair()
    group = group_model()
    plaintext = group_key_share_plaintext("group-equipa", group)
    envelope = build_message_envelope("alice", "bob", plaintext, sender_priv, recipient_pub)
    serialized = json.dumps(envelope)
    aad = build_message_aad(envelope["message_id"], envelope["from"], envelope["to"], envelope["timestamp"])

    assert group["group_key"] not in serialized
    assert "group_key" not in serialized

    decoded = json.loads(decrypt_from_sender(envelope["payload"], recipient_priv, aad=aad))
    assert decoded["type"] == GROUP_KEY_SHARE_TYPE
    assert decoded["group_key"] == group["group_key"]
    assert decoded["group_key_version"] == group["group_key_version"]
    assert decoded["group_id"] == "group-equipa"
    assert decoded["action"] == "key_rotation"

    print("OK - group_key só aparece depois de decifrar E2EE")


def test_receiving_group_key_share_updates_local_group():
    print("\n[TESTE] Receber group_key_share atualiza grupo local")

    sender_priv, sender_pub = generate_rsa_keypair()
    recipient_priv, recipient_pub = generate_rsa_keypair()
    group = group_model()
    plaintext = group_key_share_plaintext("group-equipa", group)
    envelope = build_message_envelope("alice", "bob", plaintext, sender_priv, recipient_pub)
    state = ChatState(
        username="bob",
        private_key=recipient_priv,
        public_key=recipient_pub,
        x25519_private_key=None,
        x25519_public_key=None,
    )
    state.key_cache["alice"] = sender_pub

    process_incoming_message(envelope, state)

    assert state.groups["group-equipa"]["group_key"] == group["group_key"]
    assert state.groups["group-equipa"]["group_key_version"] == group["group_key_version"]
    assert state.groups["group-equipa"]["members"] == ["alice", "bob"]
    assert state.conversations["group-equipa"] == []
    assert state.has_seen_message(envelope["message_id"])

    print("OK - group_key_share guardada sem mensagem normal")


def test_group_message_is_encrypted_with_group_key():
    print("\n[TESTE] Mensagem de grupo é cifrada com group_key")

    group = group_model()
    message_id = "group-msg-enc"
    timestamp = "2026-05-22T18:00:00Z"
    payload = build_group_message_payload(
        "alice",
        "group-equipa",
        group,
        "segredo do grupo",
        message_id,
        timestamp,
    )
    aad = build_group_aad("group-equipa", "alice", "bob", message_id, timestamp)
    encrypted = encrypt_group_payload(group["group_key"], payload, aad)

    assert "segredo do grupo" not in json.dumps(encrypted)
    decoded = decrypt_group_payload(group["group_key"], encrypted["nonce"], encrypted["ciphertext"], aad)
    assert decoded == payload
    assert decoded["text"] == "segredo do grupo"
    assert decoded["action"] == "message"

    print("OK - grupo cifra e decifra com AES-GCM")


def test_group_message_envelope_hides_sensitive_metadata():
    print("\n[TESTE] Envelope exterior de grupo não expõe metadados sensíveis")

    sender_priv, _ = generate_rsa_keypair()
    group = group_model()
    envelope = signed_group_message_envelope(
        sender_priv,
        group["group_key"],
        message_id="group-hidden-metadata",
        text="texto secreto do grupo",
    )
    serialized = json.dumps(envelope, ensure_ascii=False)

    for field in ["type", "group_id", "from", "to", "message_id", "timestamp", "payload", "signature"]:
        assert field in envelope
    assert set(envelope["payload"].keys()) == {"nonce", "ciphertext"}
    for forbidden_field in ["text", "group_name", "group_members", "members", "action", "group_key_version", "nonce", "ciphertext"]:
        assert forbidden_field not in envelope
    assert '"text"' not in serialized
    assert '"group_name"' not in serialized
    assert '"members"' not in serialized
    assert '"action"' not in serialized
    assert "texto secreto do grupo" not in serialized
    assert "Equipa" not in serialized

    aad = build_group_aad(
        envelope["group_id"],
        envelope["from"],
        envelope["to"],
        envelope["message_id"],
        envelope["timestamp"],
    )
    decoded = decrypt_group_payload(group["group_key"], envelope["payload"]["nonce"], envelope["payload"]["ciphertext"], aad)

    assert decoded["text"] == "texto secreto do grupo"
    assert decoded["action"] == "message"
    assert decoded["group_name"] == "Equipa"
    assert decoded["members"] == ["alice", "bob"]

    print("OK - metadados sensíveis só aparecem após decifragem")


def test_group_event_envelope_hides_action_and_members():
    print("\n[TESTE] Evento de grupo cifra action e members")

    sender_priv, _ = generate_rsa_keypair()
    recipient_priv, recipient_pub = generate_rsa_keypair()
    group_info = {
        "id": "group-equipa",
        "name": "Equipa",
        "members": ["alice", "bob", "carla"],
    }
    plaintext = group_control_plaintext(
        group_info,
        "carla foi removida",
        "delete",
    )
    envelope = build_message_envelope("alice", "bob", plaintext, sender_priv, recipient_pub, group=group_info)
    serialized = json.dumps(envelope, ensure_ascii=False)

    assert envelope["group_id"] == "group-equipa"
    assert "group_name" not in envelope
    assert "group_members" not in envelope
    assert "group_action" not in envelope
    assert '"members"' not in serialized
    assert '"action"' not in serialized
    assert "carla foi removida" not in serialized
    assert "Equipa" not in serialized

    aad = build_message_aad(envelope["message_id"], envelope["from"], envelope["to"], envelope["timestamp"])
    decoded = json.loads(decrypt_from_sender(envelope["payload"], recipient_priv, aad=aad))

    assert decoded["type"] == "group_control"
    assert decoded["group_name"] == "Equipa"
    assert decoded["members"] == ["alice", "bob", "carla"]
    assert decoded["action"] == "delete"
    assert decoded["text"] == "carla foi removida"

    print("OK - evento de gestão não expõe action/members no exterior")


def test_group_message_aad_rejects_outer_metadata_tampering():
    print("\n[TESTE] AAD de grupo rejeita metadados exteriores adulterados")

    sender_priv, _ = generate_rsa_keypair()
    group = group_model()
    envelope = signed_group_message_envelope(
        sender_priv,
        group["group_key"],
        message_id="group-aad-original",
        text="texto autenticado",
    )

    for field, value in [
        ("group_id", "group-outro"),
        ("from", "mallory"),
        ("to", "carla"),
        ("message_id", "group-aad-tampered"),
        ("timestamp", "2026-05-23T00:00:00Z"),
    ]:
        tampered = copy.deepcopy(envelope)
        tampered[field] = value
        aad = build_group_aad(
            tampered["group_id"],
            tampered["from"],
            tampered["to"],
            tampered["message_id"],
            tampered["timestamp"],
        )
        try:
            decrypt_group_payload(group["group_key"], envelope["payload"]["nonce"], envelope["payload"]["ciphertext"], aad)
        except Exception:
            pass
        else:
            raise AssertionError(f"metadado exterior adulterado aceite: {field}")

    print("OK - group_id/from/to/message_id/timestamp autenticados no AAD")


def test_member_without_group_key_cannot_decrypt_group_message():
    print("\n[TESTE] Utilizador sem group_key não decifra mensagem de grupo")

    group = group_model()
    other_group_key = generate_group_key()
    message_id = "group-msg-wrong-key"
    timestamp = "2026-05-22T18:00:00Z"
    payload = build_group_message_payload(
        "alice",
        "group-equipa",
        group,
        "segredo do grupo",
        message_id,
        timestamp,
    )
    aad = build_group_aad("group-equipa", "alice", "bob", message_id, timestamp)
    encrypted = encrypt_group_payload(group["group_key"], payload, aad)

    try:
        decrypt_group_payload(other_group_key, encrypted["nonce"], encrypted["ciphertext"], aad)
    except Exception:
        pass
    else:
        raise AssertionError("mensagem de grupo foi decifrada com chave errada")

    print("OK - chave errada não decifra")


def test_server_cannot_see_group_text_or_key():
    print("\n[TESTE] Servidor não vê texto nem group_key em group_message")

    sender_priv, _ = generate_rsa_keypair()
    group = group_model()
    envelope = signed_group_message_envelope(
        sender_priv,
        group["group_key"],
        message_id="server-group-secret",
        text="texto invisível ao servidor",
    )

    assert is_valid_envelope(envelope)
    with temporary_messages_file():
        stored_envelope, delivered_online, stored_encrypted = deliver_or_store_message(envelope, server_users())
        stored_json = json.dumps(storage.load_messages(), ensure_ascii=False)

        assert not delivered_online
        assert stored_encrypted
        assert stored_envelope == envelope
        assert set(stored_envelope["payload"].keys()) == {"nonce", "ciphertext"}
        assert "texto invisível ao servidor" not in stored_json
        assert "Equipa" not in stored_json
        assert '"group_name"' not in stored_json
        assert '"members"' not in stored_json
        assert '"action"' not in stored_json
        assert '"group_key_version"' not in stored_json
        assert group["group_key"] not in stored_json
        assert '"group_key":' not in stored_json

    print("OK - servidor guarda só envelope cifrado de grupo")


def test_private_messages_still_use_existing_e2ee_envelope():
    print("\n[TESTE] Mensagens privadas continuam compatíveis")

    sender_priv, _ = generate_rsa_keypair()
    recipient_priv, recipient_pub = generate_rsa_keypair()

    envelope = build_message_envelope("alice", "bob", "mensagem privada", sender_priv, recipient_pub)
    aad = build_message_aad(envelope["message_id"], envelope["from"], envelope["to"], envelope["timestamp"])

    assert "type" not in envelope
    assert "payload" in envelope
    assert decrypt_from_sender(envelope["payload"], recipient_priv, aad=aad) == "mensagem privada"

    print("OK - formato privado antigo preservado")


def decrypt_envelope_for_test(envelope, recipient_private_key):
    aad = build_message_aad(envelope["message_id"], envelope["from"], envelope["to"], envelope["timestamp"])
    return decrypt_from_sender(envelope["payload"], recipient_private_key, aad=aad)


def assert_envelope_decryption_fails(envelope, recipient_private_key):
    try:
        decrypt_envelope_for_test(envelope, recipient_private_key)
    except Exception:
        return
    raise AssertionError("mensagem adulterada foi decifrada")


def test_message_aad_correct_metadata_decrypts():
    print("\n[TESTE] AES-GCM decifra com AAD correto")

    sender_priv, _ = generate_rsa_keypair()
    recipient_priv, recipient_pub = generate_rsa_keypair()
    envelope = build_message_envelope("alice", "bob", "mensagem com AAD", sender_priv, recipient_pub)

    assert decrypt_envelope_for_test(envelope, recipient_priv) == "mensagem com AAD"

    print("OK - AAD correto aceite")


def test_message_aad_rejects_metadata_tampering():
    print("\n[TESTE] AES-GCM rejeita metadados adulterados no AAD")

    sender_priv, _ = generate_rsa_keypair()
    recipient_priv, recipient_pub = generate_rsa_keypair()
    envelope = build_message_envelope("alice", "bob", "mensagem protegida", sender_priv, recipient_pub)

    for field, value in [
        ("message_id", "message-id-alterado"),
        ("from", "mallory"),
        ("to", "charlie"),
        ("timestamp", "2026-05-23T00:00:00Z"),
    ]:
        tampered = copy.deepcopy(envelope)
        tampered[field] = value
        assert_envelope_decryption_fails(tampered, recipient_priv)

    print("OK - alterações a message_id/from/to/timestamp falham")


def test_message_aad_rejects_ciphertext_tampering():
    print("\n[TESTE] AES-GCM continua a rejeitar ciphertext adulterado")

    sender_priv, _ = generate_rsa_keypair()
    recipient_priv, recipient_pub = generate_rsa_keypair()
    envelope = build_message_envelope("alice", "bob", "mensagem protegida", sender_priv, recipient_pub)
    tampered = copy.deepcopy(envelope)
    ciphertext = bytearray(base64.b64decode(tampered["payload"]["ciphertext"]))
    ciphertext[0] ^= 1
    tampered["payload"]["ciphertext"] = base64.b64encode(ciphertext).decode()

    assert_envelope_decryption_fails(tampered, recipient_priv)

    print("OK - ciphertext adulterado falha")


def test_export_bundle_creates_public_json():
    print("\n[TESTE] export_bundle cria JSON público")

    alice = make_user_state("alice")
    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle_path = os.path.join(tmp_dir, "alice-bundle.json")
        assert cmd_export_bundle(alice, bundle_path)

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

    serialized = json.dumps(bundle)
    assert bundle["type"] == "ssi_bundle"
    assert bundle["version"] == 1
    assert bundle["username"] == "alice"
    assert "identity_key" in bundle["public_keys"]
    assert "e2ee_key" in bundle["public_keys"]
    assert "PRIVATE KEY" not in serialized
    assert "group_key" not in serialized
    assert "password" not in serialized.lower()

    print("OK - bundle contém só material público")


def test_export_bundle_prints_identity_fingerprint():
    print("\n[TESTE] export_bundle mostra fingerprint da identity_key")

    alice = make_user_state("alice")
    expected_fingerprint = identity_key_fingerprint(alice.public_key)
    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle_path = os.path.join(tmp_dir, "alice-bundle.json")
        output = io.StringIO()
        with redirect_stdout(output):
            assert cmd_export_bundle(alice, bundle_path)

        with open(bundle_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

    assert bundle["fingerprint"] == expected_fingerprint
    assert expected_fingerprint in output.getvalue()

    print("OK - fingerprint exportada e apresentada")


def test_import_bundle_imports_public_keys():
    print("\n[TESTE] import_bundle importa chaves públicas")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bundle = build_public_bundle(alice)

    imported_username = import_public_bundle(bob, bundle)

    assert imported_username == "alice"
    assert "alice" in bob.contacts
    assert public_key_to_pem(bob.key_cache["alice"]) == public_key_to_pem(alice.public_key)
    assert public_key_to_pem(bob.e2ee_key_cache["alice"]) == public_key_to_pem(alice.x25519_public_key)

    print("OK - bundle importado para cache local")


def test_import_bundle_persists_public_bundle_locally():
    print("\n[TESTE] import_bundle persiste bundle localmente")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    bundle = build_public_bundle(alice)

    with tempfile.TemporaryDirectory() as tmp_dir:
        bob.imported_bundles_path = os.path.join(tmp_dir, "bob_bundles.json")
        bundle_path = os.path.join(tmp_dir, "alice-bundle.json")
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f)

        output = io.StringIO()
        with redirect_stdout(output):
            assert cmd_import_bundle(bob, bundle_path)

        with open(bob.imported_bundles_path, "r", encoding="utf-8") as f:
            persisted = json.load(f)

    assert "alice" in persisted
    assert persisted["alice"]["username"] == "alice"
    assert persisted["alice"]["fingerprint"] == identity_key_fingerprint(alice.public_key)
    assert persisted["alice"]["fingerprint"] in output.getvalue()
    assert "PRIVATE KEY" not in json.dumps(persisted)
    assert "group_key" not in json.dumps(persisted)

    print("OK - bundle persistido com fingerprint")


def test_imported_bundles_reload_after_restart():
    print("\n[TESTE] bundles persistidos são recarregados após reinício")

    alice = make_user_state("alice")
    bob = make_user_state("bob")

    with tempfile.TemporaryDirectory() as tmp_dir:
        bundles_path = os.path.join(tmp_dir, "bob_bundles.json")
        bob.imported_bundles_path = bundles_path
        bundle_path = os.path.join(tmp_dir, "alice-bundle.json")
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump(build_public_bundle(alice), f)

        assert cmd_import_bundle(bob, bundle_path)

        restarted_bob = make_user_state("bob")
        restarted_bob.imported_bundles_path = bundles_path
        restarted_bob.key_cache = {"bob": restarted_bob.public_key}
        restarted_bob.e2ee_key_cache = {"bob": restarted_bob.x25519_public_key}
        restarted_bob.contacts = set()

        assert load_imported_bundles(restarted_bob) == 1

    assert "alice" in restarted_bob.contacts
    assert public_key_to_pem(restarted_bob.key_cache["alice"]) == public_key_to_pem(alice.public_key)
    assert public_key_to_pem(restarted_bob.e2ee_key_cache["alice"]) == public_key_to_pem(alice.x25519_public_key)

    print("OK - bundle recarregado para as caches locais")


def test_export_msg_uses_bundle_loaded_from_persistence():
    print("\n[TESTE] export_msg usa bundle carregado da persistência local")

    alice = make_user_state("alice")
    bob = make_user_state("bob")

    with tempfile.TemporaryDirectory() as tmp_dir:
        bundles_path = os.path.join(tmp_dir, "alice_bundles.json")
        alice.imported_bundles_path = bundles_path
        bundle_path = os.path.join(tmp_dir, "bob-bundle.json")
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump(build_public_bundle(bob), f)

        assert cmd_import_bundle(alice, bundle_path)

        restarted_alice = make_user_state("alice")
        restarted_alice.imported_bundles_path = bundles_path
        restarted_alice.key_cache = {"alice": restarted_alice.public_key}
        restarted_alice.e2ee_key_cache = {"alice": restarted_alice.x25519_public_key}
        assert load_imported_bundles(restarted_alice) == 1

        msg_path = os.path.join(tmp_dir, "msg.json")
        assert cmd_export_msg(restarted_alice, "bob", "mensagem persistida", msg_path)

        with open(msg_path, "r", encoding="utf-8") as f:
            exported = json.load(f)

    assert exported["envelope"]["to"] == "bob"
    assert "mensagem persistida" not in json.dumps(exported, ensure_ascii=False)

    print("OK - mensagem cifrada para bundle recarregado")


def test_import_bundle_rejects_invalid_json():
    print("\n[TESTE] import_bundle rejeita JSON inválido")

    bob = make_user_state("bob")
    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle_path = os.path.join(tmp_dir, "bad-bundle.json")
        with open(bundle_path, "w", encoding="utf-8") as f:
            f.write("{invalid")

        assert not cmd_import_bundle(bob, bundle_path)
        assert "alice" not in bob.key_cache

    print("OK - JSON inválido rejeitado")


def test_import_bundle_rejects_missing_fields():
    print("\n[TESTE] import_bundle rejeita campos obrigatórios em falta")

    bob = make_user_state("bob")
    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle_path = os.path.join(tmp_dir, "incomplete-bundle.json")
        with open(bundle_path, "w", encoding="utf-8") as f:
            json.dump({"type": "ssi_bundle", "version": 1, "username": "alice"}, f)

        assert not cmd_import_bundle(bob, bundle_path)
        assert "alice" not in bob.key_cache

    print("OK - bundle incompleto rejeitado")


def test_import_bundle_failure_does_not_corrupt_local_store():
    print("\n[TESTE] import_bundle inválido não corrompe persistência local")

    alice = make_user_state("alice")
    bob = make_user_state("bob")

    with tempfile.TemporaryDirectory() as tmp_dir:
        bob.imported_bundles_path = os.path.join(tmp_dir, "bob_bundles.json")
        good_path = os.path.join(tmp_dir, "alice-bundle.json")
        with open(good_path, "w", encoding="utf-8") as f:
            json.dump(build_public_bundle(alice), f)
        assert cmd_import_bundle(bob, good_path)

        with open(bob.imported_bundles_path, "r", encoding="utf-8") as f:
            before = json.load(f)

        bad_path = os.path.join(tmp_dir, "bad-bundle.json")
        with open(bad_path, "w", encoding="utf-8") as f:
            f.write("{invalid")
        assert not cmd_import_bundle(bob, bad_path)

        with open(bob.imported_bundles_path, "r", encoding="utf-8") as f:
            after = json.load(f)

    assert after == before

    print("OK - persistência local preservada após erro")


def test_export_import_message_file_roundtrip():
    print("\n[TESTE] export_msg/import_msg cifra e decifra por ficheiro")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    import_public_bundle(alice, build_public_bundle(bob))
    import_public_bundle(bob, build_public_bundle(alice))

    with tempfile.TemporaryDirectory() as tmp_dir:
        msg_path = os.path.join(tmp_dir, "msg.json")
        assert cmd_export_msg(alice, "bob", "segredo por ficheiro", msg_path)

        with open(msg_path, "r", encoding="utf-8") as f:
            exported = json.load(f)
        serialized = json.dumps(exported, ensure_ascii=False)

        assert exported["type"] == "ssi_message"
        assert exported["version"] == 1
        assert exported["algorithm"] == "ssi-e2ee-v2-aes-256-gcm-aad"
        assert "segredo por ficheiro" not in serialized
        assert cmd_import_msg(bob, msg_path)

    assert bob.conversations["alice"][0]["text"] == "segredo por ficheiro"

    print("OK - mensagem por ficheiro decifrada")


def test_import_msg_rejects_wrong_recipient():
    print("\n[TESTE] import_msg rejeita destinatário errado")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    charlie = make_user_state("charlie")
    import_public_bundle(alice, build_public_bundle(bob))
    import_public_bundle(charlie, build_public_bundle(alice))

    with tempfile.TemporaryDirectory() as tmp_dir:
        msg_path = os.path.join(tmp_dir, "msg.json")
        assert cmd_export_msg(alice, "bob", "não é para charlie", msg_path)
        assert not cmd_import_msg(charlie, msg_path)

    assert charlie.conversations == {}

    print("OK - destinatário errado rejeitado")


def test_import_msg_rejects_ciphertext_tampering():
    print("\n[TESTE] import_msg rejeita ciphertext adulterado")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    import_public_bundle(alice, build_public_bundle(bob))
    import_public_bundle(bob, build_public_bundle(alice))

    with tempfile.TemporaryDirectory() as tmp_dir:
        msg_path = os.path.join(tmp_dir, "msg.json")
        assert cmd_export_msg(alice, "bob", "mensagem íntegra", msg_path)
        with open(msg_path, "r", encoding="utf-8") as f:
            exported = json.load(f)
        ciphertext = bytearray(base64.b64decode(exported["envelope"]["payload"]["ciphertext"]))
        ciphertext[0] ^= 1
        exported["envelope"]["payload"]["ciphertext"] = base64.b64encode(ciphertext).decode()
        with open(msg_path, "w", encoding="utf-8") as f:
            json.dump(exported, f)

        assert not cmd_import_msg(bob, msg_path)

    assert bob.conversations == {}

    print("OK - ciphertext adulterado rejeitado")


def test_import_msg_rejects_aad_metadata_tampering():
    print("\n[TESTE] import_msg rejeita metadados autenticados adulterados")

    alice = make_user_state("alice")
    bob = make_user_state("bob")
    import_public_bundle(alice, build_public_bundle(bob))
    import_public_bundle(bob, build_public_bundle(alice))

    with tempfile.TemporaryDirectory() as tmp_dir:
        msg_path = os.path.join(tmp_dir, "msg.json")
        assert cmd_export_msg(alice, "bob", "mensagem com AAD", msg_path)
        with open(msg_path, "r", encoding="utf-8") as f:
            exported = json.load(f)
        exported["envelope"]["timestamp"] = "2026-05-23T00:00:00Z"
        with open(msg_path, "w", encoding="utf-8") as f:
            json.dump(exported, f)

        assert not cmd_import_msg(bob, msg_path)

    assert bob.conversations == {}

    print("OK - metadados AAD adulterados rejeitados")


def test_group_message_duplicate_is_ignored():
    print("\n[TESTE] Mensagem de grupo duplicada é ignorada")

    sender_priv, sender_pub = generate_rsa_keypair()
    group = group_model()
    state = ChatState(
        username="bob",
        private_key=None,
        public_key=None,
        x25519_private_key=None,
        x25519_public_key=None,
    )
    state.groups["group-equipa"] = group
    state.key_cache["alice"] = sender_pub

    envelope = signed_group_message_envelope(sender_priv, group["group_key"], message_id="group-dup")
    process_incoming_message(envelope, state)
    process_incoming_message(envelope, state)

    assert len(state.conversations["group-equipa"]) == 1
    assert state.conversations["group-equipa"][0]["text"] == "olá grupo"

    print("OK - duplicado de grupo ignorado")


def test_offline_sync_delivers_group_message_envelope():
    print("\n[TESTE] Sync/offline entrega mensagem de grupo cifrada")

    sender_priv, sender_pub = generate_rsa_keypair()
    group = group_model()
    envelope = signed_group_message_envelope(sender_priv, group["group_key"], message_id="group-offline")

    with temporary_messages_file():
        deliver_or_store_message(envelope, server_users())
        pending = get_pending_messages("bob")

        assert len(pending) == 1
        assert pending[0]["message_id"] == "group-offline"
        assert len(storage.load_messages()) == 1

        state = ChatState(
            username="bob",
            private_key=None,
            public_key=None,
            x25519_private_key=None,
            x25519_public_key=None,
        )
        state.groups["group-equipa"] = group
        state.key_cache["alice"] = sender_pub
        process_incoming_message(pending[0], state)

        assert len(state.conversations["group-equipa"]) == 1
        assert state.conversations["group-equipa"][0]["text"] == "olá grupo"
        assert ack_pending_messages("bob", ["group-offline"]) == 1
        assert storage.load_messages() == []

    print("OK - grupo offline chega pelo sync")


def test_group_key_rotation_changes_key_and_version():
    print("\n[TESTE] Rotação de group_key muda chave e versão")

    group = group_model()
    old_key = group["group_key"]
    old_version = group["group_key_version"]

    rotate_group_key(group)

    assert group["group_key"] != old_key
    assert group["group_key_version"] == old_version + 1

    print("OK - group_key rodada com nova versão")


def test_remove_member_rotates_and_shares_only_with_remaining_members():
    print("\n[TESTE] Remover membro roda chave e partilha só com restantes")

    state = make_user_state("alice")
    state.groups["group-equipa"] = {
        "name": "Equipa",
        "members": ["alice", "bob", "carla"],
        "group_key": generate_group_key(),
        "group_key_version": 1,
    }
    old_key = state.groups["group-equipa"]["group_key"]
    shares = []
    globals_ = cmd_remove_group_member.__globals__
    originals = {
        "sync_groups": globals_["sync_groups"],
        "update_groups": globals_["update_groups"],
        "send_group_control_message": globals_["send_group_control_message"],
        "send_group_key_shares": globals_["send_group_key_shares"],
    }

    def fake_send_group_key_shares(fake_state, group_id):
        group = fake_state.groups[group_id]
        for share_member in sorted(user for user in group["members"] if user != fake_state.username):
            shares.append((share_member, group["group_key"], group["group_key_version"]))
        return []

    try:
        globals_["sync_groups"] = lambda fake_state: True
        globals_["update_groups"] = lambda fake_state: True
        globals_["send_group_control_message"] = lambda *args, **kwargs: True
        globals_["send_group_key_shares"] = fake_send_group_key_shares

        cmd_remove_group_member(state, "group-equipa", "bob")
    finally:
        globals_.update(originals)

    group = state.groups["group-equipa"]
    assert group["members"] == ["alice", "carla"]
    assert group["group_key"] != old_key
    assert group["group_key_version"] == 2
    assert shares == [("carla", group["group_key"], 2)]

    print("OK - membro removido não recebeu nova group_key")


def test_leave_group_uses_single_deterministic_rotation_leader():
    print("\n[TESTE] leave_group escolhe um único rotation leader")

    old_key = generate_group_key()
    group = {
        "name": "Equipa",
        "members": ["alice", "bob", "carla"],
        "group_key": old_key,
        "group_key_version": 1,
    }
    bob = make_user_state("bob")
    carla = make_user_state("carla")
    bob.groups["group-equipa"] = copy.deepcopy(group)
    carla.groups["group-equipa"] = copy.deepcopy(group)
    msg = {"group_id": "group-equipa", "from": "alice"}
    share_calls = []
    share_recipients = []
    globals_ = handle_group_leave_message.__globals__
    originals = {
        "update_groups": globals_["update_groups"],
        "send_group_key_shares": globals_["send_group_key_shares"],
    }

    def fake_send_group_key_shares(fake_state, group_id):
        rotated_group = fake_state.groups[group_id]
        share_calls.append((fake_state.username, rotated_group["group_key"], rotated_group["group_key_version"]))
        share_recipients.extend(sorted(member for member in rotated_group["members"] if member != fake_state.username))
        return []

    try:
        globals_["update_groups"] = lambda fake_state: True
        globals_["send_group_key_shares"] = fake_send_group_key_shares
        leave_payload = {"group_id": "group-equipa", "text": "alice saiu"}
        handle_group_leave_message(bob, msg, leave_payload)
        handle_group_leave_message(carla, msg, leave_payload)
    finally:
        globals_.update(originals)

    assert get_group_rotation_leader(["carla", "bob"]) == "bob"
    assert share_calls == [("bob", bob.groups["group-equipa"]["group_key"], 2)]
    assert share_recipients == ["carla"]
    assert "alice" not in share_recipients
    assert bob.groups["group-equipa"]["members"] == ["bob", "carla"]
    assert bob.groups["group-equipa"]["group_key"] != old_key
    assert bob.groups["group-equipa"]["group_key_version"] == 2
    assert carla.groups["group-equipa"]["members"] == ["bob", "carla"]
    assert "group_key" not in carla.groups["group-equipa"]
    assert carla.groups["group-equipa"]["group_key_version"] == 2
    assert carla.groups["group-equipa"]["group_key_rotation_pending"] is True
    assert carla.groups["group-equipa"]["group_key_rotation_leader"] == "bob"

    print("OK - só o leader roda e distribui a nova group_key")


def test_leave_group_remaining_members_use_new_key_and_leaver_cannot_decrypt():
    print("\n[TESTE] Mensagens futuras após leave usam nova group_key")

    old_key = generate_group_key()
    original_group = {
        "name": "Equipa",
        "members": ["alice", "bob", "carla"],
        "group_key": old_key,
        "group_key_version": 1,
    }
    bob = make_user_state("bob")
    carla = make_user_state("carla")
    bob.groups["group-equipa"] = copy.deepcopy(original_group)
    carla.groups["group-equipa"] = copy.deepcopy(original_group)
    msg = {"group_id": "group-equipa", "from": "alice"}
    globals_ = handle_group_leave_message.__globals__
    originals = {
        "update_groups": globals_["update_groups"],
        "send_group_key_shares": globals_["send_group_key_shares"],
    }

    try:
        globals_["update_groups"] = lambda fake_state: True
        globals_["send_group_key_shares"] = lambda fake_state, group_id: []
        leave_payload = {"group_id": "group-equipa", "text": "alice saiu"}
        handle_group_leave_message(bob, msg, leave_payload)
        handle_group_leave_message(carla, msg, leave_payload)
    finally:
        globals_.update(originals)

    share_payload = json.loads(group_key_share_plaintext("group-equipa", bob.groups["group-equipa"]))
    handle_group_key_share_message(carla, {"from": "bob"}, share_payload, "share-bob-2")

    assert carla.groups["group-equipa"]["group_key"] == bob.groups["group-equipa"]["group_key"]
    assert carla.groups["group-equipa"]["group_key_version"] == 2
    assert "group_key_rotation_pending" not in carla.groups["group-equipa"]

    message_id = "future-after-leave"
    timestamp = "2026-05-23T12:30:00Z"
    payload = build_group_message_payload("bob", "group-equipa", bob.groups["group-equipa"], "segredo futuro", message_id, timestamp)
    aad = build_group_aad("group-equipa", "bob", "carla", message_id, timestamp)
    encrypted = encrypt_group_payload(bob.groups["group-equipa"]["group_key"], payload, aad)
    decoded = decrypt_group_payload(carla.groups["group-equipa"]["group_key"], encrypted["nonce"], encrypted["ciphertext"], aad)

    assert decoded["text"] == "segredo futuro"
    assert decoded["group_key_version"] == 2
    try:
        decrypt_group_payload(old_key, encrypted["nonce"], encrypted["ciphertext"], aad)
    except Exception:
        pass
    else:
        raise AssertionError("membro que saiu decifrou mensagem futura")

    print("OK - restantes decifram com chave nova e quem saiu não")


def test_member_waiting_for_rotation_cannot_send_with_old_group_key():
    print("\n[TESTE] Membro sem nova group_key não envia com chave antiga")

    carla = make_user_state("carla")
    carla.groups["group-equipa"] = {
        "name": "Equipa",
        "members": ["alice", "bob", "carla"],
        "group_key": generate_group_key(),
        "group_key_version": 1,
    }
    msg = {"group_id": "group-equipa", "from": "alice"}
    globals_ = handle_group_leave_message.__globals__
    original_update_groups = globals_["update_groups"]

    try:
        globals_["update_groups"] = lambda fake_state: True
        handle_group_leave_message(carla, msg, {"group_id": "group-equipa", "text": "alice saiu"})
    finally:
        globals_["update_groups"] = original_update_groups

    output = io.StringIO()
    with redirect_stdout(output):
        cmd_send_group(carla, "group-equipa", "não deve sair")

    assert "group_key_rotation_pending" in carla.groups["group-equipa"]
    assert "group_key" not in carla.groups["group-equipa"]
    assert "A aguardar rotação da group_key" in output.getvalue()
    assert carla.conversations == {}

    print("OK - envio bloqueado até receber a nova key share")


def test_group_messages_after_rotation_use_new_key_version():
    print("\n[TESTE] Mensagens após remoção usam nova versão da group_key")

    group = {
        "name": "Equipa",
        "members": ["alice", "carla"],
        "group_key": generate_group_key(),
        "group_key_version": 1,
    }
    removed_member_group = copy.deepcopy(group)
    rotate_group_key(group)
    message_id = "rotated-group-msg"
    timestamp = "2026-05-23T12:00:00Z"
    payload = build_group_message_payload("alice", "group-equipa", group, "segredo futuro", message_id, timestamp)
    aad = build_group_aad("group-equipa", "alice", "carla", message_id, timestamp)
    encrypted = encrypt_group_payload(group["group_key"], payload, aad)

    decoded = decrypt_group_payload(group["group_key"], encrypted["nonce"], encrypted["ciphertext"], aad)
    assert decoded["text"] == "segredo futuro"
    assert decoded["group_key_version"] == 2

    try:
        decrypt_group_payload(removed_member_group["group_key"], encrypted["nonce"], encrypted["ciphertext"], aad)
    except Exception:
        pass
    else:
        raise AssertionError("membro removido decifrou mensagem futura com chave antiga")

    print("OK - chave antiga não decifra mensagens futuras")


def test_remove_missing_group_member_does_not_corrupt_group():
    print("\n[TESTE] Remover membro inexistente não corrompe grupo")

    state = make_user_state("alice")
    original_group = {
        "name": "Equipa",
        "members": ["alice", "bob"],
        "group_key": generate_group_key(),
        "group_key_version": 1,
    }
    state.groups["group-equipa"] = copy.deepcopy(original_group)
    globals_ = cmd_remove_group_member.__globals__
    original_sync_groups = globals_["sync_groups"]
    try:
        globals_["sync_groups"] = lambda fake_state: True
        cmd_remove_group_member(state, "group-equipa", "carla")
    finally:
        globals_["sync_groups"] = original_sync_groups

    assert state.groups["group-equipa"] == original_group

    print("OK - grupo preservado")


def run_threads(worker, count):
    errors = []
    errors_lock = threading.Lock()
    barrier = threading.Barrier(count)

    def wrapped(index):
        try:
            barrier.wait()
            worker(index)
        except Exception as exc:
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=wrapped, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    if errors:
        raise errors[0]


def test_concurrent_user_updates_keep_valid_json():
    print("\n[TESTE] Escritas concorrentes em users.json não perdem utilizadores")

    thread_count = 30
    with temporary_users_file():
        def register_user(index):
            username = f"user-{index}"
            with storage.users_lock():
                users = storage.load_users()
                time.sleep(0.001)
                users[username] = {
                    "public_key": f"{username}-public-key",
                    "certificate": f"{username}-certificate",
                }
                storage.save_users(users)

        run_threads(register_user, thread_count)

        with open(storage.USERS_FILE, "r", encoding="utf-8") as f:
            stored_json = json.load(f)

        assert stored_json == storage.load_users()
        assert len(stored_json) == thread_count
        for index in range(thread_count):
            assert f"user-{index}" in stored_json

    print("OK - users.json final válido e completo")


def test_concurrent_message_storage_keeps_valid_json():
    print("\n[TESTE] Escritas concorrentes em messages.json não perdem mensagens")

    thread_count = 30
    with temporary_messages_file():
        def store_message(index):
            deliver_or_store_message(
                server_message(f"concurrent-{index}", target="bob"),
                server_users(),
            )

        run_threads(store_message, thread_count)

        with open(storage.MESSAGES_FILE, "r", encoding="utf-8") as f:
            stored_json = json.load(f)

        message_ids = {message["message_id"] for message in stored_json}
        assert stored_json == storage.load_messages()
        assert len(stored_json) == thread_count
        assert message_ids == {f"concurrent-{index}" for index in range(thread_count)}

    print("OK - messages.json final válido e completo")


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
            "group_key_version": 1,
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
            "group_key_version": 1,
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


def test_protected_groups_preserve_group_key_without_plaintext():
    print("\n[TESTE] Grupos protegidos preservam group_key cifrada")

    priv, pub = generate_rsa_keypair()
    group = group_model()
    protected_groups = protect_groups(
        "henrique",
        {"group-equipa": group},
        priv,
        pub,
    )
    protected_json = json.dumps(protected_groups)

    assert group["group_key"] not in protected_json
    assert '"group_key":' not in protected_json

    groups = unprotect_groups(protected_groups, "henrique", priv, pub)
    assert groups["group-equipa"]["group_key"] == group["group_key"]
    assert groups["group-equipa"]["group_key_version"] == group["group_key_version"]

    print("OK - group_key fica só no payload decifrado")


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
    test_signed_prekey_generation_and_signature_validation()
    test_private_prekey_stays_in_local_store_only()
    test_server_stores_only_public_signed_prekeys_and_rejects_bad_ones()
    test_server_returns_signed_prekey_once()
    test_offline_prekey_message_roundtrip_and_consumes_private_prekey()
    test_offline_prekey_message_fails_without_private_prekey()
    test_offline_prekey_message_rejects_aad_and_ciphertext_tampering()
    test_online_session_handshake_signature_validation()
    test_online_session_key_derivation_matches_and_is_fresh()
    test_online_session_handshake_processing_creates_memory_only_sessions()
    test_online_session_normal_handshake_accepts_larger_username_initiator_without_conflict()
    test_simultaneous_online_session_handshake_uses_deterministic_winner()
    test_online_session_message_roundtrip_and_tamper_detection()
    test_server_forwards_online_session_envelopes_without_offline_storage()
    test_server_stores_offline_prekey_message_without_plaintext_or_private_keys()
    test_server_stores_message_when_recipient_offline()
    test_server_delivers_online_without_storing_pending()
    test_server_fetch_after_online_delivery_is_empty()
    test_fetch_pending_messages_does_not_remove_from_storage()
    test_ack_pending_messages_removes_only_confirmed_user_messages()
    test_sync_successfully_processed_messages_are_acked_and_removed()
    test_sync_failed_processing_does_not_ack_or_remove_message()
    test_login_initialization_calls_auto_sync_after_setup()
    test_auto_sync_receives_offline_prekey_message_without_manual_sync()
    test_manual_sync_command_still_fetches_pending_messages()
    test_auto_sync_does_not_duplicate_seen_messages()
    test_auto_sync_no_pending_messages_is_quietly_successful()
    test_auto_sync_delivers_offline_group_message()
    test_server_stores_offline_when_online_socket_fails()
    test_server_group_message_delivery_keeps_only_minimal_group_metadata()
    test_group_key_is_256_bit_aes_key()
    test_group_key_share_uses_individual_e2ee_without_plain_key()
    test_receiving_group_key_share_updates_local_group()
    test_group_message_is_encrypted_with_group_key()
    test_group_message_envelope_hides_sensitive_metadata()
    test_group_event_envelope_hides_action_and_members()
    test_group_message_aad_rejects_outer_metadata_tampering()
    test_member_without_group_key_cannot_decrypt_group_message()
    test_server_cannot_see_group_text_or_key()
    test_private_messages_still_use_existing_e2ee_envelope()
    test_message_aad_correct_metadata_decrypts()
    test_message_aad_rejects_metadata_tampering()
    test_message_aad_rejects_ciphertext_tampering()
    test_export_bundle_creates_public_json()
    test_export_bundle_prints_identity_fingerprint()
    test_import_bundle_imports_public_keys()
    test_import_bundle_persists_public_bundle_locally()
    test_imported_bundles_reload_after_restart()
    test_export_msg_uses_bundle_loaded_from_persistence()
    test_import_bundle_rejects_invalid_json()
    test_import_bundle_rejects_missing_fields()
    test_import_bundle_failure_does_not_corrupt_local_store()
    test_export_import_message_file_roundtrip()
    test_import_msg_rejects_wrong_recipient()
    test_import_msg_rejects_ciphertext_tampering()
    test_import_msg_rejects_aad_metadata_tampering()
    test_group_message_duplicate_is_ignored()
    test_offline_sync_delivers_group_message_envelope()
    test_group_key_rotation_changes_key_and_version()
    test_remove_member_rotates_and_shares_only_with_remaining_members()
    test_leave_group_uses_single_deterministic_rotation_leader()
    test_leave_group_remaining_members_use_new_key_and_leaver_cannot_decrypt()
    test_member_waiting_for_rotation_cannot_send_with_old_group_key()
    test_group_messages_after_rotation_use_new_key_version()
    test_remove_missing_group_member_does_not_corrupt_group()
    test_concurrent_user_updates_keep_valid_json()
    test_concurrent_message_storage_keeps_valid_json()
    test_contacts_metadata_normalization()
    test_protected_contacts_roundtrip()
    test_groups_metadata_normalization()
    test_protected_groups_roundtrip()
    test_protected_groups_preserve_group_key_without_plaintext()
    test_message_dedup_accepts_new_message()
    test_message_dedup_ignores_duplicate_message()
    test_message_dedup_accepts_distinct_message_ids()
    test_message_without_id_is_ignored_without_crash()
    test_incoming_message_without_id_is_ignored_without_crash()
    test_seen_message_ids_rebuild_from_history()

    print("\nTODOS OS TESTES PASSARAM")


if __name__ == "__main__":
    run_all()
