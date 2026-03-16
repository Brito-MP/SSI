from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_ephemeral_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def load_ephemeral_public_key(public_bytes: bytes):
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)


def derive_session_key(shared_secret: bytes, client_pub: bytes, server_pub: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ssi-chat-secure-channel-v1" + client_pub + server_pub,
    )
    return hkdf.derive(shared_secret)