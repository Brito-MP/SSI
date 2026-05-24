#!/usr/bin/env python3
import random
import sys

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def main():
    if len(sys.argv) < 4:
        return

    try:
        tamanho_chave = int(sys.argv[1])
    except ValueError:
        return

    nome_ctxt = sys.argv[2]
    palavras = [p.encode("utf-8") for p in sys.argv[3:]]

    with open(nome_ctxt, "rb") as f:
        ctxt = f.read()

    for s in range(2 ** 16):
        random.seed(s.to_bytes(2, "big"))
        chave = random.randbytes(tamanho_chave)
        ptxt = xor_bytes(ctxt, chave)

        if any(p in ptxt for p in palavras):
            try:
                print(ptxt.decode("utf-8"), end="")
            except UnicodeDecodeError:
                print(ptxt)
            return

if __name__ == "__main__":
    main()
