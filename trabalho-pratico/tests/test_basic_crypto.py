from tests.security_common import *

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



def test_signature_tamper():
    print("\n[TESTE] Detetar adulteração")

    priv, pub = generate_rsa_keypair()

    dh1 = os.urandom(32)
    dh2 = os.urandom(32)

    signature = sign_dh_keys(priv, dh1, dh2)

    dh2_bad = os.urandom(32)

    valid = validate_signature(pub, signature, dh1, dh2_bad)

    assert not valid

    print("OK - adulteração detetada")



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



TESTS = [
    test_encryption,
    test_signature_tamper,
    test_e2ee_v2_roundtrip,
    test_e2ee_v2_fresh_ephemeral_keys,
    test_e2ee_v2_tamper_detection,
    test_e2ee_v1_compatibility,
    test_e2ee_public_key_binding_signature,
    test_e2ee_public_key_overwrite_rejected,
    test_private_messages_still_use_existing_e2ee_envelope,
    test_message_aad_correct_metadata_decrypts,
    test_message_aad_rejects_metadata_tampering,
    test_message_aad_rejects_ciphertext_tampering,
]
