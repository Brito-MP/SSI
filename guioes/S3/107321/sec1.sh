#!/bin/bash

# 1
printf "Texto do ficheiro de Lisboa\n" > lisboa.txt
printf "Texto do ficheiro do Porto\n" > porto.txt
printf "Texto do ficheiro de Braga\n" > braga.txt

# 2
ls -l lisboa.txt

# 3
chmod u=rw,g=rw,o=rw lisboa.txt
ls -l lisboa.txt

# 4
chmod u=rx,g=,o= porto.txt
ls -l porto.txt

# 5
chmod 400 braga.txt
ls -l braga.txt

# 6
mkdir -p dir1 dir2
ls -ld dir1 dir2

# 7
chmod u+x,go-x dir2
ls -ld dir2
