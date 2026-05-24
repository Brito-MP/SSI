# Respostas - Semana 5

## Q1

No `otp.py`, a chave é gerada com `os.urandom`, que é apropriado para gerar bytes aleatórios para uso criptográfico.

No `bad_otp.py`, a chave é gerada com um gerador pseudo-aleatório inseguro, inicializado com apenas 2 bytes. Assim, existem só `2^16` sementes possíveis.

Na prática, ambos conseguem cifrar e decifrar. A diferença está na segurança: no `bad_otp.py`, um atacante consegue testar todas as sementes possíveis até encontrar uma chave que produza um texto limpo plausível.

## Q2

O ataque ao `bad_otp.py` não contradiz a segurança absoluta do One-Time Pad.

A segurança absoluta do OTP exige que a chave seja verdadeiramente aleatória, tenha tamanho pelo menos igual ao da mensagem, seja secreta e nunca seja reutilizada.

Neste caso, a chave não cumpre essas condições, porque é gerada por um PRNG previsível e com poucas sementes possíveis. Portanto, a falha está na geração da chave.

## Q3

Se duas mensagens forem cifradas com a mesma chave OTP, então:

`C1 xor C2 = M1 xor M2`

A chave desaparece da operação e passa a existir informação sobre a relação entre as duas mensagens originais.

Se uma das mensagens for conhecida, a outra pode ser obtida. Mesmo sem conhecer uma das mensagens, é possível tentar palavras prováveis e explorar padrões da língua. Por isso, reutilizar a chave no OTP é inseguro.
