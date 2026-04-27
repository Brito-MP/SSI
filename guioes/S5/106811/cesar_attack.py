import sys
from typing import Iterable, Optional, Tuple


def preprocess(text: str) -> str:
	"""Return only alphabetic characters, uppercased."""
	letters = []
	for ch in text:
		if ch.isalpha():
			letters.append(ch.upper())
	return "".join(letters)


def decrypt_caesar(ciphertext: str, shift: int) -> str:
	"""Decode ciphertext with a given shift."""
	processed = preprocess(ciphertext)
	base = ord("A")
	plain_chars = []
	for ch in processed:
		pos = (ord(ch) - base - shift) % 26
		plain_chars.append(chr(base + pos))
	return "".join(plain_chars)


def find_key_and_plain(
	ciphertext: str, candidates: Iterable[str]
) -> Optional[Tuple[str, str]]:
	words = [preprocess(w) for w in candidates if preprocess(w)]
	if not words:
		return None

	for shift in range(26):
		plain = decrypt_caesar(ciphertext, shift)
		if any(word in plain for word in words):
			key_letter = chr(ord("A") + shift)
			return key_letter, plain
	return None


def parse_args(argv: list[str]) -> Tuple[str, list[str]]:
	if len(argv) < 3:
		raise ValueError(
			"Expected at least 2 arguments: <cryptogram> <word1> [word2 ...]"
		)
	return argv[1], argv[2:]


def main() -> int:
	try:
		cryptogram, words = parse_args(sys.argv)
		result = find_key_and_plain(cryptogram, words)
		if result is None:
			return 0
		key, plain = result
		print(key)
		print(plain)
		return 0
	except Exception as exc:  # pragma: no cover - small CLI utility
		sys.stderr.write(f"Error: {exc}\n")
		sys.stderr.write(
			"Usage: python3 cesar_attack.py <cryptogram> <word1> [word2 ...]\n"
		)
		return 1


if __name__ == "__main__":
	sys.exit(main())
