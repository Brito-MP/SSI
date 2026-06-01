# Semana 11 - relatorio

## Buffer overflow

Compilacao sem mitigacoes principais:

```bash
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie -g
```

Flags:

- `-fno-stack-protector`: remove stack canaries.
- `-z execstack`: marca a stack como executavel, retirando NX na stack.
- `-no-pie`: desativa PIE, tornando enderecos do binario mais previsiveis.
- `-g`: inclui informacao de debug para GDB.

Execucao normal:

```bash
./vuln "Hello"
```

O programa imprime os enderecos do buffer e da funcao sensivel, copia a entrada
para um buffer local e termina normalmente quando a entrada cabe nos 64 bytes.

Exploracao:

O erro esta em `strcpy(local, entrada)`. A funcao nao conhece o tamanho do
destino e copia ate encontrar `\0`. Com uma entrada maior do que o buffer, a
stack e sobrescrita. Em laboratorio, com canary e PIE desativados, e possivel
calcular o offset ate ao endereco de retorno e tentar redirecionar a execucao
para a funcao sensivel.

## Mitigacoes

Stack canary coloca um valor de controlo antes do endereco de retorno. Se o
overflow o alterar, o processo termina antes de usar o retorno corrompido.

NX impede execucao de codigo colocado em paginas marcadas apenas para leitura e
escrita, como a stack por defeito.

PIE/ASLR tornam os enderecos menos previsiveis. Um payload com endereco fixo
tende a falhar porque o binario e bibliotecas podem carregar em locais
diferentes.

A versao `vuln_corrigido.c` valida o comprimento da entrada antes da copia e usa
`snprintf`, limitando a escrita ao tamanho do buffer.

Compilacao da versao corrigida:

```bash
gcc -o vuln_corrigido vuln_corrigido.c -Wall -Wextra -g
```

## Format string

Compilacao com diagnosticos:

```bash
gcc -o fmtvuln fmtvuln.c -g -Wall -Wformat -Wformat-security
```

O aviso esperado indica que a string de formato nao e literal. A vulnerabilidade
esta em `printf(entrada)`: se o utilizador passar `%p %p %p`, o `printf`
interpreta esses marcadores e tenta ler argumentos que nao foram fornecidos,
mostrando valores de registos ou da stack.

Exemplo:

```bash
./fmtvuln "%p %p %p %p %p %p %p %p"
```

O output pode revelar enderecos e valores internos, incluindo o marcador
`0xcafebabe`, dependendo da plataforma e da disposicao da stack.

A correcao em `fmtvuln_corrigido.c` e usar uma string de formato fixa:

```c
printf("%s", entrada);
```

Assim, sequencias como `%p` sao texto normal e deixam de controlar o
comportamento de `printf`.

Compilacao da versao corrigida:

```bash
gcc -o fmtvuln_corrigido fmtvuln_corrigido.c -g -Wall -Wextra
```

## Comparacao

Nos dois casos, a vulnerabilidade nasce de dados externos controlarem uma
operacao perigosa: em `vuln.c`, a quantidade de bytes copiados; em `fmtvuln.c`,
a string de formato. As mitigacoes do sistema reduzem a explorabilidade, mas a
correcao principal e alterar o codigo para validar tamanhos e fixar formatos.

Os testes locais de compilacao e execucao simples ficam registados em
`logs.txt`.
