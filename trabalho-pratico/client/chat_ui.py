from client_connection import send_request
from handlers.contact_handler import cmd_add_contact, cmd_contacts
from handlers.conversation_handler import cmd_conversations, cmd_open
from handlers.message_handler import cmd_send, cmd_sync


def current_prompt(state):
    if state.active_conversation:
        return f"({state.active_conversation}) > "
    return "> "


def print_main_help():
    print("Comandos:")
    print("  contacts")
    print("  add_contact <user>")
    print("  open <user>")
    print("  conversations")
    print("  sync")
    print("  send <user> <mensagem>  (fallback/debug)")
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

        elif cmd == "add_contact" or cmd.startswith("add_contact "):
            parts = cmd.split(" ", 1)
            if len(parts) < 2 or not parts[1].strip():
                print("Uso: add_contact <user>")
                continue

            target = parts[1].strip()
            cmd_add_contact(state, target)

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

        elif cmd == "conversations":
            cmd_conversations(state)

        elif cmd == "open" or cmd.startswith("open "):
            parts = cmd.split(" ", 1)
            if len(parts) < 2 or not parts[1].strip():
                print("Uso: open <user>")
                continue
            target = parts[1].strip()

            if target not in state.contacts:
                print(f"{target} não está nos teus contactos. Usa add_contact <user>.")
                continue

            if cmd_open(state, target):
                state.active_conversation = target
                print("Modo conversa ativo. Usa /help para comandos.")

        elif cmd == "exit":
            break

        else:
            print("Comando desconhecido. Usa help.")
