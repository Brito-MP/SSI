# Semana 5 - respostas

## Cifras classicas

A cifra de Cesar desloca cada letra pelo valor da chave. Antes da cifra removi
caracteres que nao sao letras e converti tudo para maiusculas. A decifra aplica
o deslocamento contrario.

A cifra de Vigenere usa uma chave repetida. Cada letra da chave define um
deslocamento diferente, por isso e mais resistente do que Cesar, mas continua
vulneravel a analise de frequencias quando a chave e curta.

## Ataques

No ataque a Cesar testam-se as 26 chaves possiveis. Quando uma palavra esperada
aparece no texto decifrado, sao impressas a chave e a mensagem.

No ataque a Vigenere, para chaves pequenas e viavel testar todas as combinacoes.
Para chaves maiores, usei candidatos por frequencia de letras em portugues e
depois procurei palavras provaveis no texto limpo.

## OTP e bad OTP

O `otp.py` usa bytes de `os.urandom` e so e seguro se a chave tiver pelo menos o
tamanho da mensagem, for secreta e nunca for reutilizada.

O `bad_otp.py` quebra estas condicoes para demonstracao: gera uma chave com
apenas 16 bits de entropia e permite reutilizar o mesmo ficheiro de chave. Isto
torna possivel testar todas as sementes ou comparar dois criptogramas.

Se a mesma keystream for usada duas vezes:

`C1 xor C2 = M1 xor M2`

A chave desaparece da equacao. Se uma mensagem for conhecida ou parcialmente
adivinhada, obtem-se informacao direta sobre a outra.

## Testes principais

```bash
python3 cesar.py enc G "CartagoEstaNoPapo"
python3 cesar.py dec G "IGXZGMUKYZGTUVGVU"
python3 cesar_attack.py "IGXZGMUKYZGTUVGVU" BACO PAPO
python3 vigenere.py enc BACO "CifraIndecifravel"
python3 vigenere.py dec BACO "DIHFBIPRFCKTSAXSM"
python3 vigenere_attack.py 3 "PGRGARHSFHPRGCVHOJHWEPZRSCJFIVSOFRWUTBKPZGGOZPZLHWKPBR" PAPO PRAIA
```
