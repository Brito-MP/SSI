#!/usr/bin/env python3
import sys
import unicodedata

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def normaliza(texto):
    decomposed = unicodedata.normalize("NFD", texto)
    return "".join(ch for ch in decomposed.upper() if ch in ALFABETO)


def offsets(chave):
    limpa = normaliza(chave)
    if not limpa:
        raise ValueError("chave vazia")
    return [ALFABETO.index(ch) for ch in limpa]


def transforma(modo, chave, texto):
    ks = offsets(chave)
    resultado = []

    for i, letra in enumerate(normaliza(texto)):
        desloc = ks[i % len(ks)]
        if modo == "dec":
            desloc = -desloc
        resultado.append(ALFABETO[(ALFABETO.index(letra) + desloc) % 26])

    return "".join(resultado)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in {"enc", "dec"}:
        return
    try:
        print(transforma(sys.argv[1], sys.argv[2], sys.argv[3]))
    except ValueError:
        return


if __name__ == "__main__":
    main()
