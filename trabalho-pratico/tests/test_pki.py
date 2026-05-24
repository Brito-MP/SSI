from tests.security_common import *

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
    stored_public_key = public_key_to_pem(load_public_key("keys/henrique_public.pem"))

    assert stored_public_key == cert_public_key

    print("OK - chave pública corresponde ao certificado")



def test_issue_client_certificate_creates_valid_ca_signed_certificate():
    print("\n[TESTE] Ferramenta admin emite certificado de cliente válido")

    with tempfile.TemporaryDirectory() as tmp_dir:
        copy_ca_files_to_base_dir(tmp_dir)
        result = issue_client_certificate("joao", base_dir=tmp_dir)

        private_key_path = result["private_key_path"]
        public_key_path = result["public_key_path"]
        cert_path = result["cert_path"]

        assert private_key_path.exists()
        assert public_key_path.exists()
        assert cert_path.exists()

        ca_cert = x509.load_pem_x509_certificate((Path(tmp_dir) / "certs" / "ca_cert.pem").read_bytes())
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

        assert validate_certificate(cert, ca_cert, client_or_server=0)
        assert client_username_from_certificate(cert) == "joao"
        assert cn == f"{CLIENT_COMMON_NAME_PREFIX}joao"
        assert public_key_to_pem(cert.public_key()) == public_key_to_pem(load_public_key(str(public_key_path)))

    print("OK - certificado assinado pela CA e vinculado à public key/username")



def test_issue_client_certificate_rejects_invalid_usernames():
    print("\n[TESTE] Ferramenta admin rejeita usernames inválidos")

    invalid_usernames = ["", "../joao", "joao/rita", "joao\\rita", "joao rita", "joão"]
    with tempfile.TemporaryDirectory() as tmp_dir:
        copy_ca_files_to_base_dir(tmp_dir)
        for username in invalid_usernames:
            try:
                issue_client_certificate(username, base_dir=tmp_dir)
            except ValueError:
                pass
            else:
                raise AssertionError(f"username inválido aceite: {username!r}")

    print("OK - validação de username bloqueia paths e caracteres inesperados")



def test_issue_client_certificate_overwrite_requires_force():
    print("\n[TESTE] Ferramenta admin só sobrescreve com --force")

    with tempfile.TemporaryDirectory() as tmp_dir:
        copy_ca_files_to_base_dir(tmp_dir)
        first = issue_client_certificate("joao_force", base_dir=tmp_dir)
        first_cert = first["cert_path"].read_bytes()

        try:
            issue_client_certificate("joao_force", base_dir=tmp_dir)
        except FileExistsError:
            pass
        else:
            raise AssertionError("overwrite sem force foi aceite")

        second = issue_client_certificate("joao_force", force=True, base_dir=tmp_dir)
        second_cert = second["cert_path"].read_bytes()

        assert second["private_key_path"].exists()
        assert second["public_key_path"].exists()
        assert second["cert_path"].exists()
        assert second_cert != first_cert

    print("OK - overwrite exige --force explícito")



TESTS = [
    test_certificate_username_binding,
    test_certificate_public_key_binding,
    test_issue_client_certificate_creates_valid_ca_signed_certificate,
    test_issue_client_certificate_rejects_invalid_usernames,
    test_issue_client_certificate_overwrite_requires_force,
]
