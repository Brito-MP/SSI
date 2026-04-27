# Semana 5 - Respostas

## Q1

Sim. A diferença principal está na forma como a chave é gerada.

No `otp.py`, a chave é gerada com um gerador seguro, apropriado para uso criptográfico. 
Assim, a chave é imprevisível.

No `bad_otp.py`, a chave é gerada com um gerador pseudoaleatório inseguro e com uma semente de apenas 2 bytes. Existem `2^16` sementes possíveis.

Na prática, o funcionamento aparente pode parecer igual, porque ambos cifram e decifram corretamente. No entanto, o `bad_otp.py` é vulnerável, porque a chave pode ser descoberta a partir da força bruta.

## Q2

Não.

A segurança absoluta do one-time pad só se verifica quando a chave é verdadeiramente aleatória, tem tamanho igual ou superior ao texto limpo, é usada apenas uma vez e é mantida secreta.

No caso do `bad_otp.py`, a chave não é verdadeiramente aleatória, porque é gerada por um PRNG inseguro com poucas sementes possíveis. Por isso, o problema está na geração da chave, não na operação XOR do one-time pad.

## Q3

Se duas mensagens forem cifradas com a mesma chave, mesmo usando o `otp.py`, perde-se a segurança do one-time pad.

Se tivermos:

C1 = M1 XOR K

e

C2 = M2 XOR K

então:

C1 XOR C2 = M1 XOR M2

Ou seja, a chave desaparece da operação e passa a existir informação sobre a relação entre as duas mensagens originais.

Isto pode permitir ataques com base em padrões da língua, palavras prováveis ou partes conhecidas das mensagens. Por isso, reutilizar a chave torna o sistema vulnerável. A dificuldade do ataque depende do tamanho das mensagens e do conhecimento que o atacante tem sobre o conteúdo # Semana 5 - Respostas

## Q1

Sim. A diferença principal está na forma como a chave é gerada.

No `otp.py`, a chave é gerada com um gerador seguro, apropriado para uso criptográfico. 
Assim, a chave é imprevisível.

No `bad_otp.py`, a chave é gerada com um gerador pseudoaleatório inseguro e com uma semente de apenas 2 bytes. Existem `2^16` sementes possíveis.

Na prática, o funcionamento aparente pode parecer igual, porque ambos cifram e decifram corretamente. No entanto, o `bad_otp.py` é vulnerável, porque a chave pode ser descoberta a partir da força bruta.

## Q2

Não.

A segurança absoluta do one-time pad só se verifica quando a chave é verdadeiramente aleatória, tem tamanho igual ou superior ao texto limpo, é usada apenas uma vez e é mantida secreta.

No caso do `bad_otp.py`, a chave não é verdadeiramente aleatória, porque é gerada por um PRNG inseguro com poucas sementes possíveis. Por isso, o problema está na geração da chave, não na operação XOR do one-time pad.

## Q3

Se duas mensagens forem cifradas com a mesma chave, mesmo usando o `otp.py`, perde-se a segurança do one-time pad.

Se tivermos:

C1 = M1 XOR K

e

C2 = M2 XOR K

então:

C1 XOR C2 = M1 XOR M2

Ou seja, a chave desaparece da operação e passa a existir informação sobre a relação entre as duas mensagens originais.

Isto pode permitir ataques com base em padrões da língua, palavras prováveis ou partes conhecidas das mensagens. Por isso, reutilizar a chave torna o sistema vulnerável. A dificuldade do ataque depende do tamanho das mensagens e do conhecimento que o atacante tem sobre o conteúdo sendo por isso uma falha grave.