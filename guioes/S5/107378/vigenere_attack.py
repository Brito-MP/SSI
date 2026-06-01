#!/usr/bin/env python3
import itertools
import sys
import unicodedata

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
FREQ_PT = {
    "A": 14.63, "B": 1.04, "C": 3.88, "D": 4.99, "E": 12.57, "F": 1.02,
    "G": 1.30, "H": 1.28, "I": 6.18, "J": 0.40, "K": 0.02, "L": 2.78,
    "M": 4.74, "N": 5.05, "O": 10.73, "P": 2.52, "Q": 1.20, "R": 6.53,
    "S": 7.81, "T": 4.34, "U": 4.63, "V": 1.67, "W": 0.01, "X": 0.21,
    "Y": 0.01, "Z": 0.47,
}


def normaliza(texto):
    decomposed = unicodedata.normalize("NFD", texto)
    return "".join(ch for ch in decomposed.upper() if ch in ALFABETO)


def decifra(criptograma, chave):
    resultado = []
    ks = [ALFABETO.index(ch) for ch in chave]
    for i, letra in enumerate(criptograma):
        resultado.append(ALFABETO[(ALFABETO.index(letra) - ks[i % len(ks)]) % 26])
    return "".join(resultado)


def pontua(texto):
    pontos = 0.0
    for letra in texto:
        pontos += FREQ_PT.get(letra, 0.0)
    for comum in ("QUE", "DE", "AO", "OS", "AS", "PARA", "COM", "NAO"):
        pontos += texto.count(comum) * 35.0
    return pontos


def melhores_letras(coluna, limite=8):
    escolhas = []
    for indice, letra in enumerate(ALFABETO):
        claro = "".join(ALFABETO[(ALFABETO.index(ch) - indice) % 26] for ch in coluna)
        escolhas.append((pontua(claro), letra))
    escolhas.sort(reverse=True)
    return [letra for _, letra in escolhas[:limite]]


def espaco_de_chaves(tamanho, criptograma):
    if tamanho <= 4:
        return itertools.product(ALFABETO, repeat=tamanho)
    colunas = [criptograma[i::tamanho] for i in range(tamanho)]
    return itertools.product(*(melhores_letras(coluna) for coluna in colunas))


def main():
    if len(sys.argv) < 4:
        return
    try:
        tamanho = int(sys.argv[1])
    except ValueError:
        return
    if tamanho <= 0:
        return

    criptograma = normaliza(sys.argv[2])
    pistas = [normaliza(arg) for arg in sys.argv[3:]]

    melhor = None
    for letras in espaco_de_chaves(tamanho, criptograma):
        chave = "".join(letras)
        claro = decifra(criptograma, chave)
        if any(pista and pista in claro for pista in pistas):
            item = (pontua(claro), chave, claro)
            if melhor is None or item > melhor:
                melhor = item

    if melhor is not None:
        _, chave, claro = melhor
        print(chave)
        print(claro)


if __name__ == "__main__":
    main()
