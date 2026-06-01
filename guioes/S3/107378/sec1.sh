#!/usr/bin/env bash
set -euo pipefail

# Exercicios 1 a 5: ficheiros normais e bits rwx.
printf "Conteudo de teste para Lisboa\n" > lisboa.txt
printf "Conteudo de teste para Porto\n" > porto.txt
printf "Conteudo reservado de Braga\n" > braga.txt

ls -l lisboa.txt
chmod u=rw,g=rw,o=rw lisboa.txt
ls -l lisboa.txt

chmod u=rx,g=,o= porto.txt
ls -l porto.txt

chmod u=r,g=,o= braga.txt
ls -l braga.txt

# Exercicios 6 e 7: permissoes de diretorias.
mkdir -p dir1 dir2
ls -ld dir1 dir2
chmod u=rwx,g=,o= dir2
ls -ld dir2
