#!/usr/bin/env python3
import sys

NONCE_SIZE = 16


def uso():
    print("python3 chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
    sys.exit(1)


def main():
    if len(sys.argv) != 5:
        uso()

    fctxt = sys.argv[1]
    pos = int(sys.argv[2])
    antigo = sys.argv[3].encode()
    novo = sys.argv[4].encode()

    if len(antigo) != len(novo):
        print("o texto antigo e o novo devem ter o mesmo tamanho")
        sys.exit(1)

    with open(fctxt, "rb") as f:
        dados = bytearray(f.read())

    inicio = NONCE_SIZE + pos
    fim = inicio + len(antigo)
    if fim > len(dados):
        print("posição fora do criptograma")
        sys.exit(1)

    for i in range(len(antigo)):
        dados[inicio + i] ^= antigo[i] ^ novo[i]

    with open(fctxt + ".attck", "wb") as f:
        f.write(dados)


if __name__ == "__main__":
    main()
