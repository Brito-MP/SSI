#!/usr/bin/env python3
import sys
import unicodedata

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def normaliza(texto):
    decomposed = unicodedata.normalize("NFD", texto)
    return "".join(ch for ch in decomposed.upper() if ch in ALFABETO)


def deslocamento(chave):
    chave_limpa = normaliza(chave)
    if len(chave_limpa) != 1:
        raise ValueError("a chave deve ser uma letra")
    return ALFABETO.index(chave_limpa)


def cifra(modo, chave, texto):
    passo = deslocamento(chave)
    if modo == "dec":
        passo = -passo

    saida = []
    for letra in normaliza(texto):
        pos = ALFABETO.index(letra)
        saida.append(ALFABETO[(pos + passo) % len(ALFABETO)])
    return "".join(saida)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in {"enc", "dec"}:
        return
    try:
        print(cifra(sys.argv[1], sys.argv[2], sys.argv[3]))
    except ValueError:
        return


if __name__ == "__main__":
    main()
