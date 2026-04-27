import sys
import itertools
import math


FREQ_PT = {
    "A": 14.63,
    "E": 12.57,
    "O": 10.73,
    "S": 7.81,
    "R": 6.53,
    "I": 6.18,
    "N": 5.05,
    "D": 4.99,
    "M": 4.74,
    "U": 4.63,
    "T": 4.34,
    "C": 3.88,
    "L": 2.78,
    "P": 2.52,
    "V": 1.67,
    "G": 1.30,
    "H": 1.28,
    "B": 1.04,
    "F": 1.02,
    "Q": 1.20,
    "Z": 0.47,
    "J": 0.40,
    "X": 0.21,
    "K": 0.02,
    "W": 0.01,
    "Y": 0.01,
}


def preproc(text):
    result = []

    for c in text:
        if c.isalpha():
            result.append(c.upper())

    return "".join(result)


def decrypt_vigenere(ciphertext, key):
    result = []
    base = ord("A")

    for i, c in enumerate(ciphertext):
        shift = ord(key[i % len(key)]) - base
        pos = (ord(c) - base - shift) % 26
        result.append(chr(base + pos))

    return "".join(result)


def score_text(text):
    score = 0.0

    for c in text:
        freq = FREQ_PT.get(c, 0.01)
        score += math.log(freq)

    return score


def decrypt_caesar(text, shift):
    result = []
    base = ord("A")

    for c in text:
        pos = (ord(c) - base - shift) % 26
        result.append(chr(base + pos))

    return "".join(result)


def best_shifts_for_slice(text):
    candidates = []

    for shift in range(26):
        plain = decrypt_caesar(text, shift)
        score = score_text(plain)
        candidates.append((score, shift))

    candidates.sort(reverse=True)
    return [shift for _, shift in candidates]


def main():
    if len(sys.argv) < 4:
        print("Usage: python3 vigenere_attack.py <key_size> <cryptogram> <word1> [word2 ...]", file=sys.stderr)
        return 1

    key_size = int(sys.argv[1])
    cryptogram = preproc(sys.argv[2])
    words = [preproc(w) for w in sys.argv[3:]]

    slices = []

    for i in range(key_size):
        slices.append(cryptogram[i::key_size])

    shifts_by_slice = []

    for s in slices:
        shifts_by_slice.append(best_shifts_for_slice(s))

    max_candidates = 12

    while max_candidates <= 26:
        selected = [shifts[:max_candidates] for shifts in shifts_by_slice]

        for shifts in itertools.product(*selected):
            key = "".join(chr(ord("A") + s) for s in shifts)
            plain = decrypt_vigenere(cryptogram, key)

            for word in words:
                if word in plain:
                    print(key)
                    print(plain)
                    return 0

        max_candidates += 4

    return 0


if __name__ == "__main__":
    sys.exit(main())