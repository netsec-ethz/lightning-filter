#!/usr/bin/env bash
set -Eeuo pipefail

rm -f *.o libaesni.a
yasm -D__linux__ -g dwarf2 -f elf64 aesnix64asm.s -o aesnix64asm.o
ar cr libaesni.a aesnix64asm.o
