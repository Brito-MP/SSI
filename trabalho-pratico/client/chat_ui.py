import shlex

from client_connection import send_request
from handlers.contact_handler import cmd_add_contact, cmd_contacts, cmd_remove_contact
from handlers.conversation_handler import cmd_conversations, cmd_open
from handlers.file_handler import cmd_export_bundle, cmd_export_msg, cmd_import_bundle, cmd_import_msg
from handlers.message_handler import (
    cmd_create_group,
    cmd_groups,
    cmd_leave_group,
    cmd_remove_group,
    cmd_remove_group_member,
    cmd_send,
    cmd_sync,
)


def current_prompt(state):
    if state.active_conversation:
        return f"({state.active_conversation}) > "
    return "> "


def print_main_help():
    print("Comandos:")
    print("  contacts")
    print("  add_contact <user>")
    print("  remove_contact <user>")
    print("  groups")
    print("  create_group \"<nome>\" <user1,user2,...>")
    print("  remove_group <group_id>")
    print("  remove_member <group_id> <user>")
    print("  leave_group <group_id>")
    print("  chats")
    print("  open <user|group_id>")
    print("  conversations")
    print("  sync")
    print("  send <user> <mensagem>  (fallback/debug)")
    print("  export_bundle <ficheiro>")
    print("  import_bundle <ficheiro>")
    print("  export_msg <user> \"<mensagem>\" <ficheiro>")
    print("  import_msg <ficheiro>")
    print("  help")
    print("  exit")


def print_conversation_help():
    print("Comandos de conversa:")
    print("  <texto>    envia mensagem para o contacto aberto")
    print("  /back      sair da conversa")
    print("  /sync      sincronizar mensagens pendentes")
    print("  /help      mostrar ajuda")


def cmd_list_users(state):
    resp = send_request(
        state.sock,
        state.response_queue,
        state.stop_event,
        {"command": "list_users"},
    )

    if resp is None:
        print("Ligação perdida.")
        return

    if resp.get("status") != "ok":
        print(resp.get("message", "erro ao listar utilizadores"))
        return

    print("Users:", resp.get("users", []))


def run_ui_loop(state):
    while not state.stop_event.is_set():
        cmd = input(current_prompt(state)).strip()
        if not cmd:
            continue

        if state.active_conversation:
            if cmd.startswith("/"):
                special_cmd = cmd[1:].strip()

                if special_cmd == "back":
                    state.active_conversation = None
                elif special_cmd == "help":
                    print_conversation_help()
                elif special_cmd in {"sync", "inbox"}:
                    cmd_sync(state)
                else:
                    print("Comando de conversa desconhecido. Usa /help.")
            else:
                cmd_send(state, state.active_conversation, cmd)
            continue

        if cmd == "help":
            print_main_help()

        elif cmd == "contacts":
            cmd_contacts(state)

        elif cmd == "groups":
            cmd_groups(state)

        elif cmd == "chats":
            cmd_contacts(state)
            cmd_groups(state)

        elif cmd == "add_contact" or cmd.startswith("add_contact "):
            parts = cmd.split(" ", 1)
            if len(parts) < 2 or not parts[1].strip():
                print("Uso: add_contact <user>")
                continue

            target = parts[1].strip()
            cmd_add_contact(state, target)

        elif cmd == "remove_contact" or cmd.startswith("remove_contact "):
            parts = cmd.split(" ", 1)
            if len(parts) < 2 or not parts[1].strip():
                print("Uso: remove_contact <user>")
                continue

            target = parts[1].strip()
            cmd_remove_contact(state, target)

        elif cmd == "create_group" or cmd.startswith("create_group "):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue

            if len(parts) != 3 or not parts[1].strip() or not parts[2].strip():
                print("Uso: create_group <nome> <user1,user2,...>")
                continue

            _, name, members_raw = parts
            members = [member.strip() for member in members_raw.split(",")]
            cmd_create_group(state, name, members)

        elif cmd == "remove_group" or cmd.startswith("remove_group "):
            parts = cmd.split(" ", 1)
            if len(parts) < 2 or not parts[1].strip():
                print("Uso: remove_group <group_id>")
                continue

            group_id = parts[1].strip()
            cmd_remove_group(state, group_id)

        elif cmd == "remove_member" or cmd.startswith("remove_member "):
            parts = cmd.split(" ", 2)
            if len(parts) != 3 or not parts[1].strip() or not parts[2].strip():
                print("Uso: remove_member <group_id> <user>")
                continue

            _, group_id, member = parts
            cmd_remove_group_member(state, group_id, member)

        elif cmd == "leave_group" or cmd.startswith("leave_group "):
            parts = cmd.split(" ", 1)
            if len(parts) < 2 or not parts[1].strip():
                print("Uso: leave_group <group_id>")
                continue

            group_id = parts[1].strip()
            cmd_leave_group(state, group_id)

        elif cmd == "list":
            cmd_list_users(state)

        elif cmd == "send" or cmd.startswith("send "):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Uso: send <user> <mensagem>")
                continue
            _, target, text = parts
            cmd_send(state, target, text)

        elif cmd == "sync" or cmd == "inbox":
            cmd_sync(state)

        elif cmd == "export_bundle" or cmd.startswith("export_bundle "):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue
            if len(parts) != 2:
                print("Uso: export_bundle <ficheiro>")
                continue
            cmd_export_bundle(state, parts[1])

        elif cmd == "import_bundle" or cmd.startswith("import_bundle "):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue
            if len(parts) != 2:
                print("Uso: import_bundle <ficheiro>")
                continue
            cmd_import_bundle(state, parts[1])

        elif cmd == "export_msg" or cmd.startswith("export_msg "):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue
            if len(parts) != 4:
                print("Uso: export_msg <user> \"<mensagem>\" <ficheiro>")
                continue
            _, target, text, path = parts
            cmd_export_msg(state, target, text, path)

        elif cmd == "import_msg" or cmd.startswith("import_msg "):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue
            if len(parts) != 2:
                print("Uso: import_msg <ficheiro>")
                continue
            cmd_import_msg(state, parts[1])

        elif cmd == "conversations":
            cmd_conversations(state)

        elif cmd == "open" or cmd.startswith("open "):
            parts = cmd.split(" ", 1)
            if len(parts) < 2 or not parts[1].strip():
                print("Uso: open <user>")
                continue
            target = parts[1].strip()

            if target not in state.contacts and target not in state.groups:
                print(f"{target} não é contacto nem grupo conhecido.")
                continue

            if cmd_open(state, target):
                state.active_conversation = target
                print("Modo conversa ativo. Usa /help para comandos.")

        elif cmd == "exit":
            break

        else:
            print("Comando desconhecido. Usa help.")
