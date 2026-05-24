#!/usr/bin/env python3
import itertools
import sys

ORDEM_FREQ = "AEOSRINMDUTCLPVGHBFQZJXKWY"

def preproc(txt):
    letras = []
    for c in txt:
        if c.isalpha():
            letras.append(c.upper())
    return "".join(letras)

def decifra(ctxt, chave):
    res = []
    for i, c in enumerate(ctxt):
        x = ord(c) - ord("A")
        k = ord(chave[i % len(chave)]) - ord("A")
        res.append(chr(ord("A") + ((x - k) % 26)))
    return "".join(res)

def pontua(txt):
    total = 0
    for c in txt:
        if c in ORDEM_FREQ:
            total += 26 - ORDEM_FREQ.index(c)
    return total

def candidatos_coluna(coluna, n=10):
    lista = []
    for k in range(26):
        chave = chr(ord("A") + k)
        dec = decifra(coluna, chave)
        lista.append((pontua(dec), chave))
    lista.sort(reverse=True)
    return [ch for _, ch in lista[:n]]

def main():
    if len(sys.argv) < 4:
        return

    try:
        tam = int(sys.argv[1])
    except ValueError:
        return

    ctxt = preproc(sys.argv[2])
    palavras = [preproc(p) for p in sys.argv[3:]]

    if tam <= 0:
        return

    if tam <= 4:
        listas = [[chr(ord("A") + i) for i in range(26)] for _ in range(tam)]
    else:
        listas = []
        for i in range(tam):
            listas.append(candidatos_coluna(ctxt[i::tam]))

    solucoes = []
    for comb in itertools.product(*listas):
        chave = "".join(comb)
        ptxt = decifra(ctxt, chave)
        if any(p and p in ptxt for p in palavras):
            solucoes.append((pontua(ptxt), chave, ptxt))

    if len(solucoes) > 0:
        solucoes.sort(reverse=True)
        _, chave, ptxt = solucoes[0]
        print(chave)
        print(ptxt)

if __name__ == "__main__":
    main()
