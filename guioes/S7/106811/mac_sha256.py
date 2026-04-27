import os
import sys
import hashlib
import hmac


KEY_SIZE = 32


def usage():
    print("Uso:")
    print("  python3 mac_sha256.py setup <fkey>")
    print("  python3 mac_sha256.py mac <fich> <fkey>")
    print("  python3 mac_sha256.py ver <fich> <fkey>")
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def setup(fkey):
    key = os.urandom(KEY_SIZE)
    write_file(fkey, key)


def calc_mac(fich, fkey):
    key = read_file(fkey)
    msg = read_file(fich)

    if len(key) != KEY_SIZE:
        raise ValueError("A chave deve ter 32 bytes.")

    tag = hashlib.sha256(key + msg).digest()
    write_file(fich + ".mac", tag)


def verify_mac(fich, fkey):
    key = read_file(fkey)
    msg = read_file(fich)
    tag = read_file(fich + ".mac")

    if len(key) != KEY_SIZE:
        raise ValueError("A chave deve ter 32 bytes.")

    expected = hashlib.sha256(key + msg).digest()

    print(hmac.compare_digest(tag, expected))


def main():
    if len(sys.argv) < 3:
        usage()

    op = sys.argv[1]

    if op == "setup" and len(sys.argv) == 3:
        setup(sys.argv[2])
    elif op == "mac" and len(sys.argv) == 4:
        calc_mac(sys.argv[2], sys.argv[3])
    elif op == "ver" and len(sys.argv) == 4:
        verify_mac(sys.argv[2], sys.argv[3])
    else:
        usage()


if __name__ == "__main__":
    main()