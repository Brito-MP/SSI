#!/usr/bin/env python3
import sys

def preproc(txt):
    letras = []
    for c in txt:
        if c.isalpha():
            letras.append(c.upper())
    return "".join(letras)

def decifra(ctxt, k):
    res = []
    for c in preproc(ctxt):
        x = ord(c) - ord("A")
        res.append(chr(ord("A") + ((x - k) % 26)))
    return "".join(res)

def main():
    if len(sys.argv) < 3:
        return

    ctxt = sys.argv[1]
    palavras = [preproc(p) for p in sys.argv[2:]]

    for k in range(26):
        ptxt = decifra(ctxt, k)
        if any(p in ptxt for p in palavras):
            print(chr(ord("A") + k))
            print(ptxt)
            return

if __name__ == "__main__":
    main()
