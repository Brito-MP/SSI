import sys
from typing import Iterable, List, Literal


Operation = Literal["enc", "dec"]


def preprocess(text: str) -> str:
	"""Return only A-Z characters, uppercased."""
	letters: List[str] = []
	for ch in text:
		if ch.isalpha():
			letters.append(ch.upper())
	return "".join(letters)


def key_to_shifts(key: str) -> List[int]:
	"""Convert a key word to a list of shifts (A=0, B=1, ...)."""
	processed = preprocess(key)
	if not processed:
		raise ValueError("Key must contain at least one alphabetic character")
	base = ord("A")
	return [ord(ch) - base for ch in processed]


def vigenere(text: str, key: str, operation: Operation) -> str:
	"""Encode or decode text with Vigenere using the provided key word."""
	if operation not in ("enc", "dec"):
		raise ValueError("Operation must be 'enc' or 'dec'")

	shifts = key_to_shifts(key)
	processed = preprocess(text)
	result: List[str] = []
	base = ord("A")

	for idx, ch in enumerate(processed):
		shift = shifts[idx % len(shifts)]
		pos = ord(ch) - base
		if operation == "enc":
			pos = (pos + shift) % 26
		else:
			pos = (pos - shift) % 26
		result.append(chr(base + pos))

	return "".join(result)


def parse_args(argv: list[str]) -> tuple[Operation, str, str]:
	if len(argv) != 4:
		raise ValueError("Expected 3 arguments: <enc|dec> <key> <message>")
	op_raw, key, message = argv[1], argv[2], argv[3]
	op: Operation = op_raw  # type: ignore[assignment]
	if op not in ("enc", "dec"):
		raise ValueError("First argument must be 'enc' or 'dec'")
	return op, key, message


def main() -> int:
	try:
		operation, key, message = parse_args(sys.argv)
		output = vigenere(message, key, operation)
		print(output)
		return 0
	except Exception as exc:  # pragma: no cover - small CLI utility
		sys.stderr.write(f"Error: {exc}\n")
		sys.stderr.write(
			"Usage: python3 vigenere.py <enc|dec> <key> <message>\n"
		)
		return 1


if __name__ == "__main__":
	sys.exit(main())
