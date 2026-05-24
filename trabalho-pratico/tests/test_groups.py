from tests.security_common import *

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



TESTS = [
    test_auto_sync_delivers_offline_group_message,
    test_server_group_message_delivery_keeps_only_minimal_group_metadata,
    test_group_key_is_256_bit_aes_key,
    test_group_key_share_uses_individual_e2ee_without_plain_key,
    test_receiving_group_key_share_updates_local_group,
    test_group_message_is_encrypted_with_group_key,
    test_group_message_envelope_hides_sensitive_metadata,
    test_group_event_envelope_hides_action_and_members,
    test_group_message_aad_rejects_outer_metadata_tampering,
    test_member_without_group_key_cannot_decrypt_group_message,
    test_server_cannot_see_group_text_or_key,
    test_group_message_duplicate_is_ignored,
    test_offline_sync_delivers_group_message_envelope,
    test_group_key_rotation_changes_key_and_version,
    test_remove_member_rotates_and_shares_only_with_remaining_members,
    test_leave_group_uses_single_deterministic_rotation_leader,
    test_leave_group_remaining_members_use_new_key_and_leaver_cannot_decrypt,
    test_member_waiting_for_rotation_cannot_send_with_old_group_key,
    test_group_messages_after_rotation_use_new_key_version,
    test_remove_missing_group_member_does_not_corrupt_group,
]
