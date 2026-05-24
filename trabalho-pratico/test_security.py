from tests import (
    test_basic_crypto,
    test_pki,
    test_offline_prekeys,
    test_online_sessions,
    test_groups,
    test_pgp_files,
    test_storage_metadata,
)


def run_all():
    print("===== TESTES DE SEGURANÇA =====")
    modules = [
        test_basic_crypto,
        test_pki,
        test_offline_prekeys,
        test_online_sessions,
        test_groups,
        test_pgp_files,
        test_storage_metadata,
    ]
    for module in modules:
        for test in module.TESTS:
            test()
    print("\nTODOS OS TESTES PASSARAM")


if __name__ == "__main__":
    run_all()
