from crypto_utils import (
    OFFLINE_PREKEY_MESSAGE_ALGORITHM,
    OFFLINE_PREKEY_MESSAGE_TYPE,
    OFFLINE_PREKEY_MESSAGE_VERSION,
    canonical_message_bytes,
    decrypt_from_signed_prekey,
    encrypt_for_signed_prekey,
    generate_message_id,
    offline_prekey_message_signed_part,
    sign_message,
    utc_timestamp,
    verify_signature,
)
from handlers.conversation_handler import save_to_history
from handlers.prekey_handler import load_private_prekey, mark_prekey_used
from handlers.private_message_handler import get_sender_public_key


def build_offline_prekey_message_envelope(my_username, target, text, my_private_key, recipient_prekey):
    message_id = generate_message_id()
    timestamp = utc_timestamp()
    encrypted = encrypt_for_signed_prekey(
        text,
        recipient_prekey,
        my_username,
        target,
        message_id,
        timestamp,
    )
    envelope_to_sign = {
        "type": OFFLINE_PREKEY_MESSAGE_TYPE,
        "version": OFFLINE_PREKEY_MESSAGE_VERSION,
        "algorithm": OFFLINE_PREKEY_MESSAGE_ALGORITHM,
        "message_id": message_id,
        "timestamp": timestamp,
        "from": my_username,
        "to": target,
        "prekey_id": encrypted["prekey_id"],
        "ephemeral_public_key": encrypted["ephemeral_public_key"],
        "payload": encrypted["payload"],
    }
    signature = sign_message(canonical_message_bytes(offline_prekey_message_signed_part(envelope_to_sign)), my_private_key)
    return {
        **envelope_to_sign,
        "signature": signature,
    }

def process_incoming_offline_prekey_message(msg, state, message_id):
    required_fields = [
        "type",
        "algorithm",
        "timestamp",
        "from",
        "to",
        "prekey_id",
        "ephemeral_public_key",
        "payload",
        "signature",
    ]
    for required_field in required_fields:
        if required_field == "payload":
            if not isinstance(msg.get(required_field), dict):
                return
            continue
        if not isinstance(msg.get(required_field), str) or not msg.get(required_field):
            return
    if msg.get("version") != OFFLINE_PREKEY_MESSAGE_VERSION:
        return
    if msg.get("algorithm") != OFFLINE_PREKEY_MESSAGE_ALGORITHM:
        return
    if msg.get("to") != state.username:
        return
    if not all(isinstance(msg["payload"].get(field), str) and msg["payload"].get(field) for field in ["nonce", "ciphertext"]):
        return

    sender = msg.get("from")
    sender_key = get_sender_public_key(msg, state)
    if sender_key is None:
        print(f"[AVISO] sem chave pública local para validar assinatura de {sender}.")
        return

    valid = verify_signature(
        canonical_message_bytes(offline_prekey_message_signed_part(msg)),
        msg["signature"],
        sender_key,
    )
    if not valid:
        print(f"[AVISO] assinatura inválida de {sender} na mensagem offline {message_id}.")
        return

    prekey_id = msg["prekey_id"]
    try:
        private_prekey = load_private_prekey(state, prekey_id)
        plaintext = decrypt_from_signed_prekey(
            msg["payload"],
            private_prekey,
            msg["ephemeral_public_key"],
            prekey_id,
            sender,
            msg["to"],
            message_id,
            msg["timestamp"],
        )
    except Exception as exc:
        print(f"[AVISO] não foi possível decifrar mensagem offline {message_id}: {exc}")
        return

    if not save_to_history(state, msg, plaintext):
        return

    try:
        mark_prekey_used(state, prekey_id)
    except Exception as exc:
        print(f"[AVISO] mensagem decifrada, mas a prekey {prekey_id} não foi marcada como usada: {exc}")

    print(f"\n[Nova mensagem offline] {sender}: {plaintext} ({msg['timestamp']})")
