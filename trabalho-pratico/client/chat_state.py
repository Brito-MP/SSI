import os
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
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)


def ensure_keys(username: str):
    os.makedirs("keys", exist_ok=True)
    priv_path = f"keys/{username}_private.pem"
    pub_path = f"keys/{username}_public.pem"

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        private_key, public_key = generate_rsa_keypair()
        save_private_key(private_key, priv_path)
        save_public_key(public_key, pub_path)

    return load_private_key(priv_path), load_public_key(pub_path)


@dataclass
class ChatState:
    username: str
    private_key: Any
    public_key: Any
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
    key_cache_lock: threading.Lock = field(default_factory=threading.Lock)
    contacts: set = field(default_factory=set)
    active_conversation: str | None = None

    @classmethod
    def create(cls, username: str):
        private_key, public_key = ensure_keys(username)
        state = cls(username=username, private_key=private_key, public_key=public_key)
        state.key_cache[username] = public_key
        return state
