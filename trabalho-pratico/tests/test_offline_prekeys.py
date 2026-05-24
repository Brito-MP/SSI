from tests.security_common import *

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



TESTS = [
    test_signed_prekey_generation_and_signature_validation,
    test_private_prekey_stays_in_local_store_only,
    test_server_stores_only_public_signed_prekeys_and_rejects_bad_ones,
    test_server_returns_signed_prekey_once,
    test_offline_prekey_message_roundtrip_and_consumes_private_prekey,
    test_offline_prekey_message_fails_without_private_prekey,
    test_offline_prekey_message_rejects_aad_and_ciphertext_tampering,
    test_server_stores_offline_prekey_message_without_plaintext_or_private_keys,
    test_server_stores_message_when_recipient_offline,
    test_server_delivers_online_without_storing_pending,
    test_server_fetch_after_online_delivery_is_empty,
    test_fetch_pending_messages_does_not_remove_from_storage,
    test_ack_pending_messages_removes_only_confirmed_user_messages,
    test_sync_successfully_processed_messages_are_acked_and_removed,
    test_sync_failed_processing_does_not_ack_or_remove_message,
    test_login_initialization_calls_auto_sync_after_setup,
    test_auto_sync_receives_offline_prekey_message_without_manual_sync,
    test_manual_sync_command_still_fetches_pending_messages,
    test_auto_sync_does_not_duplicate_seen_messages,
    test_auto_sync_no_pending_messages_is_quietly_successful,
    test_server_stores_offline_when_online_socket_fails,
]
