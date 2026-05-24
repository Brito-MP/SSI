#!/usr/bin/env python3
import hashlib
import os
import sys
import hmac

KEY_SIZE = 32


def usage():
    print("usage:")
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


def calc_mac(key, msg):
    # prefix-MAC pedido no guião: MAC(k,m) = SHA256(k || m)
    return hashlib.sha256(key + msg).digest()


def main():
    if len(sys.argv) < 3:
        usage()

    op = sys.argv[1]

    if op == "setup" and len(sys.argv) == 3:
        write_file(sys.argv[2], os.urandom(KEY_SIZE))
        return

    if op in ("mac", "ver") and len(sys.argv) == 4:
        fich = sys.argv[2]
        fkey = sys.argv[3]
        key = read_file(fkey)
        msg = read_file(fich)
        tag = calc_mac(key, msg)

        if op == "mac":
            write_file(fich + ".mac", tag)
        else:
            old_tag = read_file(fich + ".mac")
            print(hmac.compare_digest(tag, old_tag))
        return

    usage()


if __name__ == "__main__":
    main()
