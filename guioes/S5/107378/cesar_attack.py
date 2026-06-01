#!/usr/bin/env python3
import sys
import unicodedata

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def normaliza(texto):
    decomposed = unicodedata.normalize("NFD", texto)
    return "".join(ch for ch in decomposed.upper() if ch in ALFABETO)


def decifra_com_indice(texto, indice):
    claro = []
    for letra in normaliza(texto):
        claro.append(ALFABETO[(ALFABETO.index(letra) - indice) % 26])
    return "".join(claro)


def main():
    if len(sys.argv) < 3:
        return

    criptograma = sys.argv[1]
    pistas = [normaliza(arg) for arg in sys.argv[2:]]

    for indice in range(26):
        candidato = decifra_com_indice(criptograma, indice)
        if any(pista and pista in candidato for pista in pistas):
            print(ALFABETO[indice])
            print(candidato)
            return


if __name__ == "__main__":
    main()
