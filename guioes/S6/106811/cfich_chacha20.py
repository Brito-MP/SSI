import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


KEY_SIZE = 32       # ChaCha20 usa 256 bits = 32 bytes
NONCE_SIZE = 16     # Na API da cryptography, ChaCha20 usa nonce de 16 bytes

def usage():
    print("Uso:")
    print("  python3 cfich_chacha20.py setup <fkey>")
    print("  python3 cfich_chacha20.py enc <fich> <fkey>")
    print("  python3 cfich_chacha20.py dec <fich> <fkey>")
    sys.exit(1)


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)


def load_key(fkey):
    key = read_file(fkey)
    if len(key) != KEY_SIZE:
        raise ValueError("Chave inválida: a chave ChaCha20 deve ter 32 bytes.")
    return key


def chacha20_crypt(data, key, nonce):
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data)


def do_setup(fkey):
    key = os.urandom(KEY_SIZE)
    write_file(fkey, key)
    print(f"Chave criada em '{fkey}'.")


def do_enc(fich, fkey):
    key = load_key(fkey)
    plaintext = read_file(fich)

    # Gerar nonce aleatório para esta cifragem
    nonce = os.urandom(NONCE_SIZE)

    ciphertext = chacha20_crypt(plaintext, key, nonce)

    # Guardar nonce + criptograma no ficheiro .enc
    out_file = fich + ".enc"
    write_file(out_file, nonce + ciphertext)

    print(f"Ficheiro cifrado em '{out_file}'.")


def do_dec(fich, fkey):
    key = load_key(fkey)
    content = read_file(fich)

    if len(content) < NONCE_SIZE:
        raise ValueError("Ficheiro cifrado inválido: conteúdo demasiado pequeno.")

    # Separar nonce e criptograma
    nonce = content[:NONCE_SIZE]
    ciphertext = content[NONCE_SIZE:]

    plaintext = chacha20_crypt(ciphertext, key, nonce)

    out_file = fich + ".dec"
    write_file(out_file, plaintext)

    print(f"Ficheiro decifrado em '{out_file}'.")


def main():
    if len(sys.argv) < 3:
        usage()

    op = sys.argv[1]

    try:
        if op == "setup":
            if len(sys.argv) != 3:
                usage()
            do_setup(sys.argv[2])

        elif op == "enc":
            if len(sys.argv) != 4:
                usage()
            do_enc(sys.argv[2], sys.argv[3])

        elif op == "dec":
            if len(sys.argv) != 4:
                usage()
            do_dec(sys.argv[2], sys.argv[3])

        else:
            usage()

    except Exception as e:
        print(f"Erro: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

