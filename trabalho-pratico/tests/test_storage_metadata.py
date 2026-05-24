from tests.security_common import *

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



TESTS = [
    test_concurrent_user_updates_keep_valid_json,
    test_concurrent_message_storage_keeps_valid_json,
    test_contacts_metadata_normalization,
    test_protected_contacts_roundtrip,
    test_groups_metadata_normalization,
    test_protected_groups_roundtrip,
    test_protected_groups_preserve_group_key_without_plaintext,
    test_message_dedup_accepts_new_message,
    test_message_dedup_ignores_duplicate_message,
    test_message_dedup_accepts_distinct_message_ids,
    test_message_without_id_is_ignored_without_crash,
    test_incoming_message_without_id_is_ignored_without_crash,
]
