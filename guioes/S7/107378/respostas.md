# Semana 7 - respostas

## Prefix-MAC

O `mac_sha256.py` implementa `SHA256(k || m)`. Esta construcao e vulneravel a
length extension porque o digest SHA-256 tambem representa o estado interno da
funcao depois de processar `k || m || padding`.

Se o atacante souber o tamanho da chave, consegue calcular o padding que SHA-256
teria usado para `k || m`, acrescentar novos bytes e continuar a compressao a
partir do MAC antigo. O ficheiro `.ext` contem a mensagem original, o padding
glue e a extensao; o `.ext.mac` contem o MAC forjado.

## Encrypt-then-MAC

Em encrypt-and-MAC, cifra-se a mensagem e calcula-se MAC sobre o texto limpo em
paralelo. Em MAC-then-encrypt, o MAC vai dentro do texto cifrado. Em
encrypt-then-MAC, cifra-se primeiro e autentica-se o criptograma e os parametros
publicos depois.

A terceira opcao e a mais simples de validar com seguranca: no
`pbenc_aes_ctr_hmac.py`, o HMAC e verificado antes de decifrar. Foram derivadas
duas chaves independentes, uma para AES-CTR e outra para HMAC-SHA256.

## AEAD

O `pbenc_aes_gcm.py` usa AES-GCM, que ja combina cifra e autenticacao. Isto
evita gerir um HMAC separado e reduz o risco de usar uma ordem insegura. O nonce
continua a ter de ser unico para cada cifra com a mesma chave.
