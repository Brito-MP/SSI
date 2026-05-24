from tests.security_common import *

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



TESTS = [
    test_online_session_handshake_signature_validation,
    test_online_session_key_derivation_matches_and_is_fresh,
    test_online_session_handshake_processing_creates_memory_only_sessions,
    test_online_session_normal_handshake_accepts_larger_username_initiator_without_conflict,
    test_simultaneous_online_session_handshake_uses_deterministic_winner,
    test_online_session_message_roundtrip_and_tamper_detection,
    test_server_forwards_online_session_envelopes_without_offline_storage,
]
