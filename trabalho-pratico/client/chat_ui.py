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
    print("Comandos principais:")
    print("  users                         listar utilizadores do servidor")
    print("  contacts                      listar contactos")
    print("  add <user>                    adicionar contacto")
    print("  remove <user>                 remover contacto")
    print("")
    print("  chats                         listar conversas")
    print("  open <user|group_id>          abrir conversa")
    print("")
    print("  groups                        listar grupos")
    print("  help groups                   ajuda para comandos de grupo")
    print("  files                         ajuda para comandos por ficheiro")
    print("")
    print("  sync                          sincronizar mensagens manualmente")
    print("  help                          mostrar esta ajuda")
    print("  exit                          sair")


def print_group_help():
    print("Comandos de grupo:")
    print("  group_create \"<nome>\" user1,user2")
    print("  group_remove <group_id>")
    print("  group_kick <group_id> <user>")
    print("  group_leave <group_id>")


def print_files_help():
    print("Comandos por ficheiro:")
    print("  export_bundle <ficheiro>")
    print("  import_bundle <ficheiro>")
    print("  export_msg <user> \"<mensagem>\" <ficheiro>")
    print("  import_msg <ficheiro>")


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


def is_command(cmd, name):
    return cmd == name or cmd.startswith(f"{name} ")


def command_arg(cmd, usage):
    parts = cmd.split(" ", 1)
    if len(parts) < 2 or not parts[1].strip():
        print(usage)
        return None
    return parts[1].strip()


def parse_group_create(cmd, usage):
    try:
        parts = shlex.split(cmd)
    except ValueError:
        print(usage)
        return None

    if len(parts) != 3 or not parts[1].strip() or not parts[2].strip():
        print(usage)
        return None

    _, name, members_raw = parts
    members = [member.strip() for member in members_raw.split(",")]
    return name, members


def run_ui_loop(state):
    while not state.stop_event.is_set():
        try:
            cmd = input(current_prompt(state)).strip()
        except EOFError:
            break
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

        elif cmd == "help groups":
            print_group_help()

        elif cmd == "files":
            print_files_help()

        elif cmd in {"users", "list"}:
            cmd_list_users(state)

        elif cmd == "contacts":
            cmd_contacts(state)

        elif cmd == "groups":
            cmd_groups(state)

        elif cmd in {"chats", "conversations"}:
            cmd_conversations(state)

        elif is_command(cmd, "add"):
            target = command_arg(cmd, "Uso: add <user>")
            if target is None:
                continue

            cmd_add_contact(state, target)

        elif is_command(cmd, "remove"):
            target = command_arg(cmd, "Uso: remove <user>")
            if target is None:
                continue

            cmd_remove_contact(state, target)

        elif is_command(cmd, "add_contact"):
            target = command_arg(cmd, "Uso: add_contact <user>")
            if target is None:
                continue

            cmd_add_contact(state, target)

        elif is_command(cmd, "remove_contact"):
            target = command_arg(cmd, "Uso: remove_contact <user>")
            if target is None:
                continue

            cmd_remove_contact(state, target)

        elif is_command(cmd, "group_create"):
            parsed = parse_group_create(cmd, "Uso: group_create \"<nome>\" user1,user2")
            if parsed is None:
                continue

            name, members = parsed
            cmd_create_group(state, name, members)

        elif is_command(cmd, "create_group"):
            parsed = parse_group_create(cmd, "Uso: create_group <nome> <user1,user2,...>")
            if parsed is None:
                continue

            name, members = parsed
            cmd_create_group(state, name, members)

        elif is_command(cmd, "group_remove"):
            group_id = command_arg(cmd, "Uso: group_remove <group_id>")
            if group_id is None:
                continue

            cmd_remove_group(state, group_id)

        elif is_command(cmd, "remove_group"):
            group_id = command_arg(cmd, "Uso: remove_group <group_id>")
            if group_id is None:
                continue

            cmd_remove_group(state, group_id)

        elif is_command(cmd, "group_kick"):
            parts = cmd.split(" ", 2)
            if len(parts) != 3 or not parts[1].strip() or not parts[2].strip():
                print("Uso: group_kick <group_id> <user>")
                continue

            _, group_id, member = parts
            cmd_remove_group_member(state, group_id, member)

        elif is_command(cmd, "remove_member"):
            parts = cmd.split(" ", 2)
            if len(parts) != 3 or not parts[1].strip() or not parts[2].strip():
                print("Uso: remove_member <group_id> <user>")
                continue

            _, group_id, member = parts
            cmd_remove_group_member(state, group_id, member)

        elif is_command(cmd, "group_leave"):
            group_id = command_arg(cmd, "Uso: group_leave <group_id>")
            if group_id is None:
                continue

            cmd_leave_group(state, group_id)

        elif is_command(cmd, "leave_group"):
            group_id = command_arg(cmd, "Uso: leave_group <group_id>")
            if group_id is None:
                continue

            cmd_leave_group(state, group_id)

        elif is_command(cmd, "send"):
            parts = cmd.split(" ", 2)
            if len(parts) < 3:
                print("Uso: send <user> <mensagem>")
                continue
            _, target, text = parts
            cmd_send(state, target, text)

        elif cmd == "sync" or cmd == "inbox":
            cmd_sync(state)

        elif is_command(cmd, "export_bundle"):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue
            if len(parts) != 2:
                print("Uso: export_bundle <ficheiro>")
                continue
            cmd_export_bundle(state, parts[1])

        elif is_command(cmd, "import_bundle"):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue
            if len(parts) != 2:
                print("Uso: import_bundle <ficheiro>")
                continue
            cmd_import_bundle(state, parts[1])

        elif is_command(cmd, "export_msg"):
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

        elif is_command(cmd, "import_msg"):
            try:
                parts = shlex.split(cmd)
            except ValueError as exc:
                print(f"Comando inválido: {exc}")
                continue
            if len(parts) != 2:
                print("Uso: import_msg <ficheiro>")
                continue
            cmd_import_msg(state, parts[1])

        elif is_command(cmd, "open"):
            target = command_arg(cmd, "Uso: open <user|group_id>")
            if target is None:
                continue

            with state.conversations_lock:
                has_conversation = target in state.conversations

            if not has_conversation and target not in state.contacts and target not in state.groups:
                print("Não encontrei essa conversa. Usa `contacts`, `groups` ou `add <user>`.")
                continue

            if cmd_open(state, target):
                state.active_conversation = target
                print("Modo conversa ativo. Usa /help para comandos.")

        elif cmd == "exit":
            break

        else:
            print("Comando desconhecido. Escreve `help` para ver os comandos.")
