from tests.security_common import *

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



TESTS = [
    test_export_bundle_creates_public_json,
    test_export_bundle_prints_identity_fingerprint,
    test_import_bundle_imports_public_keys,
    test_import_bundle_persists_public_bundle_locally,
    test_imported_bundles_reload_after_restart,
    test_export_msg_uses_bundle_loaded_from_persistence,
    test_import_bundle_rejects_invalid_json,
    test_import_bundle_rejects_missing_fields,
    test_import_bundle_failure_does_not_corrupt_local_store,
    test_export_import_message_file_roundtrip,
    test_import_msg_rejects_wrong_recipient,
    test_import_msg_rejects_ciphertext_tampering,
    test_import_msg_rejects_aad_metadata_tampering,
]
