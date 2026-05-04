import queue
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from crypto_utils import (
    generate_rsa_keypair,
    generate_x25519_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)


def ensure_keys(username: str):
    keys_dir = ROOT_DIR / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / f"{username}_private.pem"
    pub_path = keys_dir / f"{username}_public.pem"

    if not priv_path.exists() or not pub_path.exists():
        private_key, public_key = generate_rsa_keypair()
        save_private_key(private_key, str(priv_path))
        save_public_key(public_key, str(pub_path))

    return load_private_key(str(priv_path)), load_public_key(str(pub_path))


def ensure_x25519_keys(username: str):
    keys_dir = ROOT_DIR / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / f"{username}_x25519_private.pem"
    pub_path = keys_dir / f"{username}_x25519_public.pem"

    if not priv_path.exists() or not pub_path.exists():
        private_key, public_key = generate_x25519_keypair()
        save_private_key(private_key, str(priv_path))
        save_public_key(public_key, str(pub_path))

    return load_private_key(str(priv_path)), load_public_key(str(pub_path))


@dataclass
class ChatState:
    username: str
    private_key: Any
    public_key: Any
    x25519_private_key: Any
    x25519_public_key: Any
    sock: Any = None
    session_key: bytes | None = None
    response_queue: queue.Queue = field(default_factory=queue.Queue)
    stop_event: threading.Event = field(default_factory=threading.Event)
    conversations: dict = field(default_factory=dict)
    conversations_lock: threading.Lock = field(default_factory=threading.Lock)
    groups: dict = field(default_factory=dict)
    groups_deleted: set = field(default_factory=set)
    groups_dirty: bool = False
    key_cache: dict = field(default_factory=dict)
    e2ee_key_cache: dict = field(default_factory=dict)
    key_cache_lock: threading.Lock = field(default_factory=threading.Lock)
    contacts: set = field(default_factory=set)
    active_conversation: str | None = None

    @classmethod
    def create(cls, username: str):
        private_key, public_key = ensure_keys(username)
        x25519_private_key, x25519_public_key = ensure_x25519_keys(username)
        state = cls(
            username=username,
            private_key=private_key,
            public_key=public_key,
            x25519_private_key=x25519_private_key,
            x25519_public_key=x25519_public_key,
        )
        state.key_cache[username] = public_key
        state.e2ee_key_cache[username] = x25519_public_key
        return state
