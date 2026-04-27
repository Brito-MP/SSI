## Q1

Usar um NONCE fixo, por exemplo tudo a zero, é uma má prática.

Na cifra ChaCha20, a mesma chave com o mesmo NONCE gera sempre a mesma sequência pseudoaleatória. Se duas mensagens forem cifradas com a mesma chave e o mesmo NONCE, é reutilizada a mesma keystream.

Nesse caso, um atacante pode combinar os criptogramas e obter informação sobre os textos limpos. Por isso, o NONCE deve ser diferente em cada cifragem feita com a mesma chave.

## Q2

Numa cifra sequencial como ChaCha20, o criptograma é obtido fazendo XOR entre o texto limpo e a keystream.

Se for alterado apenas um bit do texto limpo e for usada a mesma chave e o mesmo NONCE, apenas o bit correspondente do criptograma é alterado.

Assim, alterar um bit do texto limpo afeta apenas um bit do criptograma.

## Q3

No modo CTR, o comportamento é semelhante ao de uma cifra sequencial. Alterar um bit do criptograma altera apenas o bit correspondente no texto limpo após a decifragem.

No modo CBC, alterar um bit de um bloco do criptograma afeta a decifragem desse bloco e também altera o bit correspondente no bloco seguinte.

Assim, em CBC, um bit alterado no criptograma corrompe completamente o bloco atual de texto limpo e altera um bit no bloco seguinte. No caso do IV, alterar um bit do IV altera apenas o bit correspondente no primeiro bloco de texto limpo.

## Q4

O programa `chacha20_int_attck.py` funciona bem em criptogramas produzidos por ChaCha20, porque ChaCha20 é uma cifra sequencial. Como o criptograma é obtido por XOR, é possível alterar partes conhecidas do texto limpo manipulando diretamente os bytes correspondentes do criptograma.

No AES-CTR, o ataque tem um efeito semelhante, porque CTR também funciona como uma cifra sequencial: alterar bytes do criptograma altera diretamente os bytes correspondentes no texto limpo.

No AES-CBC, o mesmo ataque não funciona da mesma forma. Alterações no criptograma afetam blocos inteiros durante a decifragem e podem também provocar erros no padding. Lofo, não conseguimos uma alteração controlada de texto limpo com a mesma facilidade.

## Q5

Na versão com password-based encryption, o salt e o NONCE têm funções diferentes.

O salt é usado na derivação da chave a partir da passphrase. O seu objetivo é garantir que a mesma passphrase possa originar chaves diferentes em cifragens diferentes e dificultar ataques com tabelas pré-computadas.

O NONCE é usado pela cifra ChaCha20. O seu objetivo é garantir que a keystream gerada seja diferente em cada cifragem feita com a mesma chave.

Ambos são necessários, porque protegem partes diferentes do processo. O salt protege a derivação da chave e o NONCE protege a utilização da cifra sequencial.