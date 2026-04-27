import sys
import random


def xor_bytes(data, key):
    result = bytearray()

    for i in range(len(data)):
        result.append(data[i] ^ key[i])

    return bytes(result)


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 bad_otp_attack.py <key_size> <cipher_file> <word1> [word2 ...]", file=sys.stderr)
        return 1

    key_size = int(sys.argv[1])
    cipher_file = sys.argv[2]
    words = [w.lower() for w in sys.argv[3:]]

    with open(cipher_file, "rb") as f:
        ciphertext = f.read()

    for seed_value in range(2 ** 16):
        seed = seed_value.to_bytes(2, "big")
        random.seed(seed)
        key = random.randbytes(key_size)

        plaintext_bytes = xor_bytes(ciphertext, key)

        try:
            plaintext = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue

        plaintext_lower = plaintext.lower()

        found = True

        for word in words:
            if word not in plaintext_lower:
                found = False
                break

        if found:
            print(plaintext, end="")
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())