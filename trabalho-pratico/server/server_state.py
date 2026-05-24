import threading

online_users = {}
online_users_lock = threading.Lock()


def set_online_user(username: str, sock):
    with online_users_lock:
        online_users[username] = sock


def is_user_online(username: str) -> bool:
    with online_users_lock:
        return username in online_users


def get_online_user_socket(username: str):
    with online_users_lock:
        return online_users.get(username)


def remove_online_user_if_socket(username: str, sock):
    with online_users_lock:
        if online_users.get(username) is sock:
            del online_users[username]
