# Semana 6 - respostas

## Nonce fixo

Em ChaCha20, a cifra gera uma keystream a partir da chave e do nonce. Se o nonce
for repetido com a mesma chave, a keystream repete-se. Dois criptogramas podem
entao ser combinados por XOR e passam a revelar relacoes entre os textos limpos.

## Alterar bits

Numa cifra de fluxo, alterar um bit do texto limpo altera o bit correspondente
do criptograma. O contrario tambem e verdade: alterar um bit do criptograma
altera diretamente esse bit no texto limpo decifrado.

No modo AES-CTR acontece o mesmo, porque o CTR transforma a cifra por blocos
numa cifra de fluxo. No AES-CBC, alterar um bit de um bloco de criptograma torna
o bloco atual imprevisivel e altera um bit no bloco seguinte. Se a alteracao for
no IV, so afeta diretamente o primeiro bloco.

## Ataque de integridade

O `chacha20_int_attck.py` troca texto conhecido por outro texto do mesmo tamanho
fazendo XOR no criptograma. Funciona em ChaCha20 e tambem em CTR se nao houver
autenticacao. Em CBC o efeito nao e uma substituicao direta na mesma posicao.

## Password-based encryption

Uma password humana nao deve ser usada diretamente como chave criptografica. A
KDF transforma a password numa chave de tamanho correto e torna ataques de
dicionario mais caros. O salt e aleatorio, fica guardado no ficheiro cifrado e
evita que a mesma password produza sempre a mesma chave.

O nonce/IV tambem fica guardado com o criptograma. Nao e secreto, mas tem de ser
novo em cada cifra.
