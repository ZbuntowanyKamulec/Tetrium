# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Probe: the access right after OUT 92h (A20 gate) with no jump in between (tests/pm/pm39.s).
# Real mode: FFFF:0510 (100500h, 22222222h; masked: 000500h, 11111111h) loaded right after
# disabling and after enabling the gate.  Paging: linear 40100h maps to 140100h (77777777h;
# masked 040100h, 88888888h), its translation already in the TLB, loaded right after
# disabling and after enabling.  Prints the four values.
.intel_syntax noprefix
.include "mac.s"
R  = 0x3000                             # results (DS base 10000h)
PT = 0x21000
.code16
.org 0x100
start:
    cli
    xor  ax, ax
    mov  es, ax                         # 0000
    mov  ax, 0xFFFF
    mov  fs, ax                         # FFFF: FFFF0-10FFEF
    mov  al, 2                          # A20 on (settled: far jump)
    out  0x92, al
    .byte 0xEA
    .word 1f, 0x1000
1:  mov  dword ptr es:[0x500], 0x11111111
    mov  dword ptr fs:[0x510], 0x22222222           # 100500
    mov  eax, fs:[0x510]
    mov  al, 0
    out  0x92, al
    mov  eax, fs:[0x510]                            # right after: 000500?
    mov  [R], eax
    mov  al, 2
    out  0x92, al
    mov  eax, fs:[0x510]                            # right after: 100500?
    mov  [R + 4], eax
    # ---- protected mode, paging
    lgdt [gdtr]
    mov  eax, cr0
    or   al, 1
    mov  cr0, eax
    .byte 0x66, 0xEA
    .long pm32
    .word 0x08
.code32
pm32:
    mov  ax, 0x10
    mov  ds, ax
    mov  ss, ax
    mov  esp, 0x2F000
    mov  ax, 0x18
    mov  es, ax                         # flat
    mov  fs, ax
    mov  edi, 0x20000
    mov  ecx, 1024
    xor  eax, eax
    cld
    rep  stosd
    mov  dword ptr es:[0x20000], PT + 7
    mov  edi, PT
    mov  eax, 7
    mov  ecx, 0x40
1:  stosd
    add  eax, 0x1000
    loop 1b
    mov  dword ptr es:[PT + 0x40*4], 0x140007       # 40000 -> 140000
    mov  dword ptr es:[0x140100], 0x77777777
    mov  dword ptr es:[0x040100], 0x88888888
    mov  eax, 0x20000
    mov  cr3, eax
    mov  eax, cr0
    or   eax, 0x80000000
    mov  cr0, eax
    jmp  1f
1:  mov  eax, fs:[0x40100]                          # (translation cached)
    mov  al, 0
    out  0x92, al
    mov  eax, fs:[0x40100]                          # right after: 040100?
    mov  [R + 8], eax
    mov  al, 2
    out  0x92, al
    mov  eax, fs:[0x40100]                          # right after: 140100?
    mov  [R + 12], eax
    mov  eax, cr0
    and  eax, 0x7FFFFFFF
    mov  cr0, eax
    jmp  2f
2:  PS   "a20out rm off on: "
    PH   [R]
    PH   [R + 4]
    PS   "| paging off on: "
    PH   [R + 8]
    PH   [R + 12]
    jmp  done
.include "lib.s"

.org 0x1000
gdtr:   .word gdt_end - gdt - 1
        .long 0x10000 + gdt
.align 8
gdt:
    .quad 0
    desc 0x10000, 0xFFFF, 0x9A, 4           # 08 code32
    desc 0x10000, 0xFFFFF, 0x92, 0xC        # 10 data32
    desc 0, 0xFFFFF, 0x92, 0xC              # 18 flat data
gdt_end:
