#!/usr/bin/env python3
import hashlib
import hmac
import os
import sys

KEY_LEN = 32


def usage():
    print("uso: python3 mac_sha256.py setup <fkey>")
    print("uso: python3 mac_sha256.py mac <fich> <fkey>")
    print("uso: python3 mac_sha256.py ver <fich> <fkey>")
    sys.exit(1)


def read_all(path):
    with open(path, "rb") as input_file:
        return input_file.read()


def write_all(path, data):
    with open(path, "wb") as output:
        output.write(data)


def prefix_mac(key, message):
    return hashlib.sha256(key + message).digest()


def main():
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "setup":
            write_all(sys.argv[2], os.urandom(KEY_LEN))
            return

        if len(sys.argv) == 4 and sys.argv[1] in {"mac", "ver"}:
            message = read_all(sys.argv[2])
            key = read_all(sys.argv[3])
            tag = prefix_mac(key, message)
            if sys.argv[1] == "mac":
                write_all(sys.argv[2] + ".mac", tag)
            else:
                stored = read_all(sys.argv[2] + ".mac")
                print(hmac.compare_digest(tag, stored))
            return

        usage()
    except OSError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
