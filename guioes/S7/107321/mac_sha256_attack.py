#!/usr/bin/env python3
import struct
import sys

# O guião fixa chaves SHA256 com 32 bytes.
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


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_padding(message_len):
    # Padding SHA256 para uma mensagem com message_len bytes.
    pad = b"\x80"
    pad += b"\x00" * ((56 - (message_len + 1) % 64) % 64)
    pad += struct.pack(">Q", message_len * 8)
    return pad


def compress(chunk, h):
    w = list(struct.unpack(">16L", chunk))
    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

    a, b, c, d, e, f, g, hh = h
    for i in range(64):
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hh + s1 + ch + K[i] + w[i]) & 0xffffffff
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (s0 + maj) & 0xffffffff
        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return [
        (h[0] + a) & 0xffffffff,
        (h[1] + b) & 0xffffffff,
        (h[2] + c) & 0xffffffff,
        (h[3] + d) & 0xffffffff,
        (h[4] + e) & 0xffffffff,
        (h[5] + f) & 0xffffffff,
        (h[6] + g) & 0xffffffff,
        (h[7] + hh) & 0xffffffff,
    ]


def extend_sha256(old_digest, extra, processed_len):
    h = list(struct.unpack(">8L", old_digest))
    data = extra + sha256_padding(processed_len + len(extra))
    for i in range(0, len(data), 64):
        h = compress(data[i:i + 64], h)
    return struct.pack(">8L", *h)


def main():
    if len(sys.argv) != 3:
        print("usage: python3 mac_sha256_attack.py <fich> <ext>")
        sys.exit(1)

    fich = sys.argv[1]
    ext = sys.argv[2].encode()

    with open(fich, "rb") as f:
        msg = f.read()
    with open(fich + ".mac", "rb") as f:
        old_mac = f.read()

    glue = sha256_padding(KEY_SIZE + len(msg))
    forged_msg = msg + glue + ext

    # Antes de acrescentar ext, SHA256 já processou key || msg || glue.
    processed = KEY_SIZE + len(msg) + len(glue)
    forged_mac = extend_sha256(old_mac, ext, processed)

    with open(fich + ".ext", "wb") as f:
        f.write(forged_msg)
    with open(fich + ".ext.mac", "wb") as f:
        f.write(forged_mac)


if __name__ == "__main__":
    main()
