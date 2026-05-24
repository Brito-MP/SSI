import os
import base64
import copy
import io
import json
import shutil
import sys
import tempfile
import threading
import time
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT_DIR = Path(__file__).resolve().parents[1]
CLIENT_DIR = ROOT_DIR / "client"
if str(CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(CLIENT_DIR))

from common.certificates import load_client_certificate
from common.security import CLIENT_COMMON_NAME_PREFIX, client_username_from_certificate, sign_dh_keys, validate_certificate, validate_signature

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
    load_public_key,
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
from server.server_state import reserve_online_user
from client_start import initialize_logged_in_client
from tools.issue_client_cert import issue_client_certificate


def generate_rsa_keypair():
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


def copy_ca_files_to_base_dir(base_dir):
    base_path = Path(base_dir)
    certs_dir = base_path / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)
    source_certs_dir = ROOT_DIR / "certs"
    shutil.copyfile(source_certs_dir / "ca_cert.pem", certs_dir / "ca_cert.pem")
    shutil.copyfile(source_certs_dir / "ca_key.pem", certs_dir / "ca_key.pem")


def decode_sent_json(sock):
    assert len(sock.sent) == 1
    return json.loads(sock.sent[0].decode("utf-8").strip())
