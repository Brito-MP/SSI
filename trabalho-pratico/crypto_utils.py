import os
import json
import base64
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


# Guarda a chave privada no disco local do cliente.
# O servidor nunca deve ter acesso a este ficheiro.
def save_private_key(private_key, path: str):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, "wb") as f:
        f.write(pem)


# Guarda a chave pública para que o utilizador a possa publicar no servidor.
def save_public_key(public_key, path: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(pem)


# Lê a chave privada local do utilizador.
def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# Lê uma chave pública guardada em PEM.
def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# Converte a chave pública para texto PEM para a enviar pelo protocolo.
def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


# Reconstrói uma chave pública a partir de texto PEM.
def public_key_from_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode())


# Cifra uma mensagem para um destinatário específico.
# Gera uma chave AES aleatória para esta mensagem, cifra o texto com AES-GCM
# e encapsula a chave AES com a chave pública RSA do destinatário.
def encrypt_for_recipient(plaintext: str, recipient_public_key):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }


# Decifra uma mensagem recebida por este utilizador.
def decrypt_from_sender(payload: dict, recipient_private_key) -> str:
    encrypted_key = base64.b64decode(payload["encrypted_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    aes_key = recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


# Assina dados com a chave privada do remetente.
def sign_message(data: bytes, private_key) -> str:
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


# Verifica a assinatura de um remetente.
def verify_signature(data: bytes, signature_b64: str, public_key) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# Serializa um dicionário sempre da mesma maneira antes de assinar/verificar.
def canonical_message_bytes(message_dict: dict) -> bytes:
    return json.dumps(message_dict, sort_keys=True, separators=(",", ":")).encode()


# Gera um identificador único para cada mensagem.
def generate_message_id() -> str:
    return str(uuid.uuid4())


# Cria um timestamp UTC em formato ISO 8601.
def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()
