#!/usr/bin/env python3
import sys

NONCE_LEN = 16


def usage():
    print("uso: python3 chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
    sys.exit(1)


def main():
    if len(sys.argv) != 5:
        usage()

    try:
        position = int(sys.argv[2])
    except ValueError:
        usage()
    if position < 0:
        usage()

    old = sys.argv[3].encode()
    new = sys.argv[4].encode()
    if len(old) != len(new):
        print("erro: textos antigo e novo devem ter o mesmo tamanho", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as input_file:
        forged = bytearray(input_file.read())

    start = NONCE_LEN + position
    stop = start + len(old)
    if stop > len(forged):
        print("erro: posicao fora do criptograma", file=sys.stderr)
        sys.exit(1)

    for i, (before, after) in enumerate(zip(old, new)):
        forged[start + i] ^= before ^ after

    with open(sys.argv[1] + ".attck", "wb") as output:
        output.write(forged)


if __name__ == "__main__":
    main()
