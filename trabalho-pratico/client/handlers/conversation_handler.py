def save_to_history(state, msg, plaintext):
    message_id = msg.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        return False

    for required_field in ["timestamp", "from", "to"]:
        if required_field not in msg:
            return False

    if not state.mark_message_seen(message_id):
        return False

    if msg.get("group_id"):
        peer = msg["group_id"]
        group_name = msg.get("group_name", peer)
        members = msg.get("group_members", [])
        if isinstance(members, list):
            clean_members = sorted({m.strip() for m in members if isinstance(m, str) and m.strip()})
        else:
            clean_members = []
        if peer not in state.groups:
            state.groups[peer] = {
                "name": group_name,
                "members": clean_members,
            }
            state.groups_dirty = True
        else:
            group = state.groups[peer]
            if not group.get("members") and clean_members:
                group["members"] = clean_members
                state.groups_dirty = True
            if group.get("name") in {None, "", peer} and group_name != peer:
                group["name"] = group_name
                state.groups_dirty = True
    else:
        peer = msg["from"] if msg["from"] != state.username else msg["to"]

    record = {
        "message_id": message_id,
        "timestamp": msg["timestamp"],
        "from": msg["from"],
        "to": msg["to"],
        "text": plaintext,
        "group_id": msg.get("group_id"),
        "group_name": msg.get("group_name"),
    }

    with state.conversations_lock:
        state.conversations.setdefault(peer, []).append(record)

    return True


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
            label = state.groups.get(peer, {}).get("name", peer)
            summaries.append((last["timestamp"], peer, label, last["from"], last["text"]))

    if not summaries:
        print("Sem conversas locais.")
        return

    for timestamp, peer, label, sender, text in sorted(summaries, key=lambda item: item[0], reverse=True):
        preview = text if len(text) <= 40 else text[:37] + "..."
        print(f"{label} ({peer}) | {timestamp} | {sender}: {preview}")


def cmd_open(state, target):
    with state.conversations_lock:
        msgs = list(state.conversations.get(target, []))

    label = state.groups.get(target, {}).get("name", target)
    print(f"--- Conversa com {label} ---")

    if not msgs:
        print(f"Sem histórico local com {target}.")
        return True

    for msg in msgs:
        sender_label = "eu" if msg["from"] == state.username else msg["from"]
        print(f"[{msg['timestamp']}] {sender_label}: {msg['text']}")

    return True
