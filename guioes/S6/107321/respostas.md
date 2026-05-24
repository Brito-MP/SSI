# Respostas - Semana 6

## Q1

Usar um NONCE fixo em ChaCha20 faz com que, para a mesma chave, seja gerada sempre a mesma keystream. Isso quebra a segurança da cifra sequencial, porque dois criptogramas cifrados com a mesma chave e o mesmo NONCE podem ser comparados através de XOR. Na prática, se o atacante souber ou adivinhar parte de uma mensagem, consegue retirar informação sobre outras mensagens cifradas com a mesma keystream.

## Q2

Numa cifra sequencial síncrona como ChaCha20, cifrar consiste essencialmente em fazer XOR entre o texto limpo e a keystream. Por isso, se se alterar apenas 1 bit no texto limpo e se usar a mesma chave e o mesmo NONCE, altera-se apenas o bit correspondente no criptograma. Não há difusão sobre os restantes bits.

## Q3

No modo CTR, a situação é semelhante a uma cifra sequencial: alterar 1 bit do criptograma altera apenas 1 bit do texto limpo depois de decifrar.

No modo CBC, alterar 1 bit num bloco de criptograma afeta todo o bloco de texto limpo correspondente de forma imprevisível e altera também o bit correspondente no bloco seguinte. Se a alteração for feita no IV, apenas o bit correspondente do primeiro bloco de texto limpo é alterado.

## Q4

O programa `chacha20_int_attck.py` funciona bem contra ChaCha20 porque a cifra é baseada em XOR e não tem autenticação. Se soubermos o texto limpo numa certa posição, conseguimos alterar o criptograma para obter outro texto limpo nessa posição.

No AES-CTR o mesmo tipo de ataque também pode funcionar, porque CTR também transforma o AES numa cifra de fluxo baseada em XOR.

No AES-CBC o ataque não funciona da mesma forma. Um bit flip no criptograma tem efeitos diferentes: corrompe um bloco inteiro e altera um bit no bloco seguinte. Logo, não permite substituir diretamente uma palavra por outra na mesma posição como acontece em ChaCha20/CTR.

## Q5

O salt e o NONCE têm funções diferentes.

O salt é usado na KDF, por exemplo PBKDF2, para derivar a chave a partir da passphrase. Serve para evitar que a mesma passphrase gere sempre a mesma chave e dificulta ataques com tabelas pré-computadas.

O NONCE é usado pela cifra ChaCha20 para garantir que a keystream não se repete quando se cifra com a mesma chave.

São ambos necessários: o salt protege o processo de derivação da chave e o NONCE protege a utilização da cifra. Nenhum deles precisa de ser secreto, mas ambos devem ser guardados juntamente com o criptograma para permitir a decifra.

## Comandos usados para teste

```bash
python3 cfich_chacha20.py setup chacha.key
python3 cfich_chacha20.py enc msg.txt chacha.key
python3 cfich_chacha20.py dec msg.txt.enc chacha.key

python3 chacha20_int_attck.py msg.txt.enc 18 "100" "900"
python3 cfich_chacha20.py dec msg.txt.enc.attck chacha.key

python3 cfich_aes_cbc.py setup aes_cbc.key
python3 cfich_aes_cbc.py enc msg.txt aes_cbc.key
python3 cfich_aes_cbc.py dec msg.txt.enc aes_cbc.key

python3 cfich_aes_ctr.py setup aes_ctr.key
python3 cfich_aes_ctr.py enc msg.txt aes_ctr.key
python3 cfich_aes_ctr.py dec msg.txt.enc aes_ctr.key

echo "segredo" | python3 pbenc_chacha20.py enc msg.txt
echo "segredo" | python3 pbenc_chacha20.py dec msg.txt.enc
```
