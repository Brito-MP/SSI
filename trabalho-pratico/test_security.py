"""
Testes básicos de segurança para o projeto SSI chat.

Executar com:
python3 test_security.py
"""

import os
import base64
import copy
import json
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
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
from handlers.message_handler import (
    build_group_message_envelope,
    build_group_message_payload,
    build_message_envelope,
    group_key_share_plaintext,
    process_incoming_message,
)
import storage
from crypto_utils import (
    build_message_aad,
    decrypt_group_payload,
    decrypt_from_sender,
    e2ee_public_key_binding_bytes,
    encrypt_group_payload,
    encrypt_for_recipient,
    encrypt_for_recipient_v2,
    generate_group_key,
    generate_x25519_keypair,
    GROUP_KEY_SHARE_TYPE,
    GROUP_MESSAGE_TYPE,
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
from server.server import (
    can_set_e2ee_public_key,
    deliver_or_store_message,
    is_valid_envelope,
    online_users,
    online_users_lock,
    pop_pending_messages,
)


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
    aad = build_message_aad(message_id, "alice", target, timestamp)
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

        assert pop_pending_messages("bob") == []
        assert storage.load_messages() == []

    print("OK - sync pós-entrega online vazio")


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


def test_server_group_message_delivery_keeps_group_fields():
    print("\n[TESTE] Servidor mantém campos de grupo na entrega online")

    with temporary_messages_file():
        target_socket = FakeSocket()
        with online_users_lock:
            online_users["bob"] = target_socket

        envelope, delivered_online, stored_encrypted = deliver_or_store_message(
            server_message("group-online-1", group=True),
            server_users(),
        )
        delivered = decode_sent_json(target_socket)

        assert delivered_online
        assert not stored_encrypted
        assert storage.load_messages() == []
        assert envelope["group_id"] == "group-equipa"
        assert delivered["group_id"] == "group-equipa"
        assert delivered["group_members"] == ["alice", "bob"]

    print("OK - campos de grupo preservados")


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
    assert decoded["group_id"] == "group-equipa"

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
    aad = build_message_aad(message_id, "alice", "bob", timestamp)
    encrypted = encrypt_group_payload(group["group_key"], payload, aad)

    assert "segredo do grupo" not in json.dumps(encrypted)
    decoded = decrypt_group_payload(group["group_key"], encrypted["nonce"], encrypted["ciphertext"], aad)
    assert decoded == payload

    print("OK - grupo cifra e decifra com AES-GCM")


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
    aad = build_message_aad(message_id, "alice", "bob", timestamp)
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
        assert "texto invisível ao servidor" not in stored_json
        assert group["group_key"] not in stored_json
        assert "group_key" not in stored_json

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
        pending = pop_pending_messages("bob")

        assert len(pending) == 1
        assert pending[0]["message_id"] == "group-offline"

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
        assert storage.load_messages() == []

    print("OK - grupo offline chega pelo sync")


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
    assert "group_key" not in protected_json

    groups = unprotect_groups(protected_groups, "henrique", priv, pub)
    assert groups["group-equipa"]["group_key"] == group["group_key"]

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
    test_server_stores_message_when_recipient_offline()
    test_server_delivers_online_without_storing_pending()
    test_server_fetch_after_online_delivery_is_empty()
    test_server_stores_offline_when_online_socket_fails()
    test_server_group_message_delivery_keeps_group_fields()
    test_group_key_is_256_bit_aes_key()
    test_group_key_share_uses_individual_e2ee_without_plain_key()
    test_receiving_group_key_share_updates_local_group()
    test_group_message_is_encrypted_with_group_key()
    test_member_without_group_key_cannot_decrypt_group_message()
    test_server_cannot_see_group_text_or_key()
    test_private_messages_still_use_existing_e2ee_envelope()
    test_message_aad_correct_metadata_decrypts()
    test_message_aad_rejects_metadata_tampering()
    test_message_aad_rejects_ciphertext_tampering()
    test_group_message_duplicate_is_ignored()
    test_offline_sync_delivers_group_message_envelope()
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
