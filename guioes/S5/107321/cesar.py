#!/usr/bin/env python3
import sys

def preproc(txt):
    letras = []
    for c in txt:
        if c.isalpha():
            letras.append(c.upper())
    return "".join(letras)

def cifra(texto, chave, modo):
    k = ord(chave) - ord("A")
    if modo == "dec":
        k = -k

    res = []
    for c in preproc(texto):
        x = ord(c) - ord("A")
        res.append(chr(ord("A") + ((x + k) % 26)))
    return "".join(res)

def main():
    if len(sys.argv) != 4:
        return

    op = sys.argv[1]
    chave = preproc(sys.argv[2])
    msg = sys.argv[3]

    if len(chave) != 1:
        return

    if op == "enc" or op == "dec":
        print(cifra(msg, chave, op))

if __name__ == "__main__":
    main()
