def save_to_history(state, msg, plaintext):
    peer = msg["from"] if msg["from"] != state.username else msg["to"]

    record = {
        "message_id": msg["message_id"],
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "text": plaintext,
    }

    with state.conversations_lock:
        state.conversations.setdefault(peer, []).append(record)


def cmd_conversations(state):
    with state.conversations_lock:
        if not state.conversations:
            print("Sem conversas locais.")
            return

        summaries = []
        for peer, msgs in state.conversations.items():
            if not msgs:
                continue
            last = msgs[-1]
            summaries.append((last["timestamp"], peer, last["from"], last["text"]))

    if not summaries:
        print("Sem conversas locais.")
        return

    for timestamp, peer, sender, text in sorted(summaries, key=lambda item: item[0], reverse=True):
        preview = text if len(text) <= 40 else text[:37] + "..."
        print(f"{peer} | {timestamp} | {sender}: {preview}")


def cmd_open(state, target):
    with state.conversations_lock:
        msgs = list(state.conversations.get(target, []))

    print(f"--- Conversa com {target} ---")

    if not msgs:
        print(f"Sem histórico local com {target}.")
        return True

    for msg in msgs:
        sender_label = "eu" if msg["from"] == state.username else msg["from"]
        print(f"[{msg['timestamp']}] {sender_label}: {msg['text']}")

    return True
