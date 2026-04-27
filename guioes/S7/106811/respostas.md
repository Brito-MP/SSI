## Q1

A mensagem considerada é:

`http://www.super-secret.com/manage?id=1001&role=user&perm=read`

A chave usada pelo prefix-MAC tem 32 bytes e a mensagem tem 62 bytes. Assim, o SHA256 calcula o padding sobre um total de 94 bytes, correspondentes a:

`chave || mensagem`

O padding acrescentado é:

```text
80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
02 f0
```

Este padding tem 34 bytes.

O valor final `02 f0` corresponde ao tamanho original em bits:

`94 * 8 = 752 bits = 0x02f0`

Este padding é acrescentado antes da extensão `&admin=true`.

## Q2

O programa `pbenc_aes_ctr_hmac.py` usa AES em modo CTR e calcula separadamente um HMAC-SHA256 sobre o criptograma, seguindo a estratégia encrypt-then-MAC.

O ficheiro produzido contém:

`salt || nonce || ciphertext || tag_hmac`

Neste caso, a tag HMAC tem 32 bytes, porque é produzida com SHA256.

O programa `pbenc_aes_gcm.py` usa AES-GCM, que já é uma cifra autenticada. O ficheiro produzido contém:

`salt || nonce || ciphertext_com_tag_gcm`

No AES-GCM, a tag de autenticação é incluída no resultado da cifragem e tem normalmente 16 bytes.

Assim, para a mesma mensagem, o ficheiro produzido por `pbenc_aes_ctr_hmac.py` tende a ser maior, porque adiciona uma tag HMAC de 32 bytes. Já o `pbenc_aes_gcm.py` adiciona uma tag de 16 bytes.

A diferença no tamanho resulta principalmente do mecanismo de autenticação usado. Em ambos os casos não é necessário padding, porque tanto CTR como GCM funcionam como modos de cifra sequencial.