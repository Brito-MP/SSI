# Respostas - Semana 7

## Q1

Na construção prefix-MAC `MAC(k,m) = SHA256(k || m)`, o atacante não conhece a chave, mas sabe que a chave tem 32 bytes. Para a mensagem
`http://www.super-secret.com/manage?id=1001&role=user&perm=read`, a função SHA256 faz padding sobre `key || mensagem`.

A mensagem tem 62 bytes e a chave tem 32 bytes, logo o comprimento interno antes do padding é 94 bytes. O padding acrescentado é:

```text
80 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 f0
```

Tem 34 bytes. O último valor `02 f0` corresponde a 752 bits, isto é, `94 * 8`.

## Q2

Em `pbenc_aes_ctr_hmac.py`, o ficheiro cifrado contém o `salt`, o `nonce`, o criptograma e uma tag HMAC-SHA256 separada. Como o HMAC-SHA256 tem 32 bytes, o ficheiro final fica maior por causa dessa tag.

Em `pbenc_aes_gcm.py`, a autenticação já faz parte do modo AES-GCM. A biblioteca devolve o criptograma com a tag de autenticação GCM incluída, normalmente com 16 bytes. Assim, para a mesma mensagem, a versão AES-GCM tende a produzir um ficheiro menor do que a versão AES-CTR + HMAC.

Ambas as abordagens usam uma cifra baseada em CTR e não precisam de padding. A diferença principal é a forma como a integridade é garantida: HMAC externo no primeiro caso e autenticação integrada no GCM no segundo.
