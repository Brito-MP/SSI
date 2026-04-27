import sys
from typing import Literal


Operation = Literal["enc", "dec"]


def preprocess(text: str) -> str:
	"""Return only A-Z characters, uppercased."""
	letters = []
	for ch in text:
		if ch.isalpha():
			letters.append(ch.upper())
	return "".join(letters)


def key_to_shift(key: str) -> int:
	"""Convert a single letter key (A-Z) to a numeric shift 0-25."""
	if len(key) != 1 or not key.isalpha():
		raise ValueError("Key must be a single alphabetic character (A-Z)")
	return ord(key.upper()) - ord("A")


def caesar(text: str, shift: int, operation: Operation) -> str:
	"""Apply Caesar cipher shift; enc adds shift, dec subtracts shift."""
	if operation not in ("enc", "dec"):
		raise ValueError("Operation must be 'enc' or 'dec'")

	processed = preprocess(text)
	result = []
	for ch in processed:
		base = ord("A")
		pos = ord(ch) - base
		if operation == "enc":
			pos = (pos + shift) % 26
		else:  # dec
			pos = (pos - shift) % 26
		result.append(chr(base + pos))
	return "".join(result)


def parse_args(argv: list[str]) -> tuple[Operation, int, str]:
	if len(argv) != 4:
		raise ValueError("Expected 3 arguments: <enc|dec> <key A-Z> <message>")
	operation_raw, key_raw, message = argv[1], argv[2], argv[3]
	operation: Operation = operation_raw  # type: ignore[assignment]
	shift = key_to_shift(key_raw)
	if operation not in ("enc", "dec"):
		raise ValueError("First argument must be 'enc' or 'dec'")
	return operation, shift, message


def main() -> int:
	try:
		operation, shift, message = parse_args(sys.argv)
		output = caesar(message, shift, operation)
		print(output)
		return 0
	except Exception as exc:  # pragma: no cover - small CLI utility
		sys.stderr.write(f"Error: {exc}\n")
		sys.stderr.write("Usage: python3 cesar_cypher.py <enc|dec> <key A-Z> <message>\n")
		return 1


if __name__ == "__main__":
	sys.exit(main())
