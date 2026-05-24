from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives import serialization

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, path: str):
    pem = private_key_to_pem(private_key).encode()
    with open(path, "wb") as f:
        f.write(pem)

def private_key_to_pem(private_key) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

def save_public_key(public_key, path: str):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(pem)

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def public_key_from_pem(pem: str):
    return serialization.load_pem_public_key(pem.encode())

def x25519_public_key_from_pem(pem: str):
    public_key = public_key_from_pem(pem)
    if not isinstance(public_key, x25519.X25519PublicKey):
        raise TypeError("chave pública E2EE não é X25519")
    return public_key

def x25519_private_key_from_pem(pem: str):
    private_key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise TypeError("chave privada E2EE não é X25519")
    return private_key

def _x25519_public_raw(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
