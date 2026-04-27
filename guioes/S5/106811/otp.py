import sys
import secrets


def xor_bytes(data, key):
    if len(key) < len(data):
        raise ValueError("A chave tem de ter tamanho igual ou superior ao ficheiro.")

    result = bytearray()

    for i in range(len(data)):
        result.append(data[i] ^ key[i])

    return bytes(result)


def setup(size, key_file):
    key = secrets.token_bytes(size)

    with open(key_file, "wb") as f:
        f.write(key)


def enc(message_file, key_file):
    with open(message_file, "rb") as f:
        message = f.read()

    with open(key_file, "rb") as f:
        key = f.read()

    ciphertext = xor_bytes(message, key)

    with open(message_file + ".enc", "wb") as f:
        f.write(ciphertext)


def dec(cipher_file, key_file):
    with open(cipher_file, "rb") as f:
        ciphertext = f.read()

    with open(key_file, "rb") as f:
        key = f.read()

    plaintext = xor_bytes(ciphertext, key)

    with open(cipher_file + ".dec", "wb") as f:
        f.write(plaintext)


def main():
    if len(sys.argv) != 4:
        print("Usage:", file=sys.stderr)
        print("python3 otp.py setup <num_bytes> <key_file>", file=sys.stderr)
        print("python3 otp.py enc <message_file> <key_file>", file=sys.stderr)
        print("python3 otp.py dec <cipher_file> <key_file>", file=sys.stderr)
        return 1

    op = sys.argv[1]

    if op == "setup":
        setup(int(sys.argv[2]), sys.argv[3])
    elif op == "enc":
        enc(sys.argv[2], sys.argv[3])
    elif op == "dec":
        dec(sys.argv[2], sys.argv[3])
    else:
        print("Operação inválida.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())