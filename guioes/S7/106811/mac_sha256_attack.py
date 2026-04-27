import sys
import struct


KEY_SIZE = 32

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_padding(message_len):
    padding = b"\x80"

    while (message_len + len(padding)) % 64 != 56:
        padding += b"\x00"

    padding += struct.pack(">Q", message_len * 8)

    return padding


def compress(chunk, state):
    w = list(struct.unpack(">16I", chunk))

    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

    a, b, c, d, e, f, g, h = state

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (h + S1 + ch + K[i] + w[i]) & 0xffffffff
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff

        h = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return [
        (state[0] + a) & 0xffffffff,
        (state[1] + b) & 0xffffffff,
        (state[2] + c) & 0xffffffff,
        (state[3] + d) & 0xffffffff,
        (state[4] + e) & 0xffffffff,
        (state[5] + f) & 0xffffffff,
        (state[6] + g) & 0xffffffff,
        (state[7] + h) & 0xffffffff,
    ]


def sha256_continue(data, previous_digest, previous_len):
    state = list(struct.unpack(">8I", previous_digest))

    data_to_process = data + sha256_padding(previous_len + len(data))

    for i in range(0, len(data_to_process), 64):
        state = compress(data_to_process[i:i + 64], state)

    return struct.pack(">8I", *state)


def main():
    if len(sys.argv) != 3:
        print("Uso: python3 mac_sha256_attack.py <fich> <ext>")
        sys.exit(1)

    fich = sys.argv[1]
    ext = sys.argv[2].encode()

    msg = read_file(fich)
    original_mac = read_file(fich + ".mac")

    if len(original_mac) != 32:
        raise ValueError("O MAC original deve ter 32 bytes.")

    glue_padding = sha256_padding(KEY_SIZE + len(msg))

    forged_msg = msg + glue_padding + ext

    previous_len = KEY_SIZE + len(msg) + len(glue_padding)
    forged_mac = sha256_continue(ext, original_mac, previous_len)

    write_file(fich + ".ext", forged_msg)
    write_file(fich + ".ext.mac", forged_mac)


if __name__ == "__main__":
    main()