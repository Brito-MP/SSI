#!/usr/bin/env python3
import sys

def preproc(txt):
    letras = []
    for c in txt:
        if c.isalpha():
            letras.append(c.upper())
    return "".join(letras)

def cifra(texto, chave, op):
    texto = preproc(texto)
    chave = preproc(chave)

    if chave == "":
        return ""

    res = []
    for i, c in enumerate(texto):
        x = ord(c) - ord("A")
        k = ord(chave[i % len(chave)]) - ord("A")

        if op == "dec":
            k = -k

        res.append(chr(ord("A") + ((x + k) % 26)))
    return "".join(res)

def main():
    if len(sys.argv) != 4:
        return

    op = sys.argv[1]
    if op == "enc" or op == "dec":
        print(cifra(sys.argv[3], sys.argv[2], op))

if __name__ == "__main__":
    main()
