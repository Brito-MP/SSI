#!/usr/bin/env python3
import struct
import sys

KEY_LEN = 32
ROUND_CONSTANTS = [
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


def rotr(value, count):
    return ((value >> count) | (value << (32 - count))) & 0xffffffff


def sha256_padding(length_bytes):
    padding = b"\x80"
    padding += b"\x00" * ((56 - (length_bytes + 1) % 64) % 64)
    padding += struct.pack(">Q", length_bytes * 8)
    return padding


def compress(block, state):
    schedule = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = rotr(schedule[i - 15], 7) ^ rotr(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3)
        s1 = rotr(schedule[i - 2], 17) ^ rotr(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10)
        schedule.append((schedule[i - 16] + s0 + schedule[i - 7] + s1) & 0xffffffff)

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        big_s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        choose = (e & f) ^ (~e & g)
        t1 = (h + big_s1 + choose + ROUND_CONSTANTS[i] + schedule[i]) & 0xffffffff
        big_s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t2 = (big_s0 + majority) & 0xffffffff
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & 0xffffffff, c, b, a, (t1 + t2) & 0xffffffff

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


def continue_hash(previous_digest, extension, processed_len):
    state = list(struct.unpack(">8I", previous_digest))
    tail = extension + sha256_padding(processed_len + len(extension))
    for offset in range(0, len(tail), 64):
        state = compress(tail[offset:offset + 64], state)
    return struct.pack(">8I", *state)


def read_all(path):
    with open(path, "rb") as input_file:
        return input_file.read()


def write_all(path, data):
    with open(path, "wb") as output:
        output.write(data)


def main():
    if len(sys.argv) != 3:
        print("uso: python3 mac_sha256_attack.py <fich> <ext>")
        sys.exit(1)

    path = sys.argv[1]
    extension = sys.argv[2].encode()
    message = read_all(path)
    old_tag = read_all(path + ".mac")

    glue = sha256_padding(KEY_LEN + len(message))
    forged_message = message + glue + extension
    processed = KEY_LEN + len(message) + len(glue)
    forged_tag = continue_hash(old_tag, extension, processed)

    write_all(path + ".ext", forged_message)
    write_all(path + ".ext.mac", forged_tag)


if __name__ == "__main__":
    main()
