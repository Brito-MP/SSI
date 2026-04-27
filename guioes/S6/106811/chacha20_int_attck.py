#!/usr/bin/env python3

import sys


NONCE_SIZE = 16   # no ficheiro .enc do programa anterior: nonce || ciphertext


def usage():
    print("Uso:")
    print("  python3 chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main():
    if len(sys.argv) != 5:
        usage()

    fctxt = sys.argv[1]
    pos = int(sys.argv[2])
    ptxt_at_pos = sys.argv[3].encode()
    new_ptxt_at_pos = sys.argv[4].encode()

    if len(ptxt_at_pos) != len(new_ptxt_at_pos):
        print("Erro: <ptxtAtPos> e <newPtxtAtPos> devem ter o mesmo comprimento.")
        sys.exit(1)

    content = read_file(fctxt)

    if len(content) < NONCE_SIZE:
        print("Erro: ficheiro cifrado inválido.")
        sys.exit(1)

    # Formato do ficheiro: nonce || ciphertext
    nonce = content[:NONCE_SIZE]
    ciphertext = bytearray(content[NONCE_SIZE:])

    if pos < 0 or pos + len(ptxt_at_pos) > len(ciphertext):
        print("Erro: posição fora dos limites do criptograma.")
        sys.exit(1)

    # Ataque:
    # C = P XOR K
    # Se conhecemos P e queremos P', então:
    # C' = C XOR P XOR P'
    for i in range(len(ptxt_at_pos)):
        ciphertext[pos + i] ^= ptxt_at_pos[i] ^ new_ptxt_at_pos[i]

    attacked_content = nonce + bytes(ciphertext)
    out_file = fctxt + ".attck"
    write_file(out_file, attacked_content)

    print(f"Criptograma manipulado gravado em '{out_file}'.")


if __name__ == "__main__":
    main()