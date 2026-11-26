# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Paging paths the RTL coverage report (tools/vcov.py) found unused: a #PF from a not-present
# page directory entry (the handler maps it, the access restarts) and INVLPG / MOV CR3 while
# the L2 TLB is still clearing after a CR3 write.  (pm11's page map.)
# Results go to the log (compared store by store in lockstep).
.intel_syntax noprefix
.macro desc base, limit, acc, fl
    .word (\limit) & 0xFFFF
    .word (\base) & 0xFFFF
    .byte ((\base) >> 16) & 0xFF
    .byte \acc
    .byte (((\limit) >> 16) & 0x0F) | ((\fl) << 4)
    .byte ((\base) >> 24) & 0xFF
.endm
.macro gate off, sel, acc
    .word \off
    .word \sel
    .byte 0, \acc
    .word 0
.endm
.macro logr r                       # append a register to the log
    mov  ebx, [logp]
    mov  [ebx], \r
    add  dword ptr [logp], 4
.endm
.macro a20rm v                      # real mode: set the gate, far jump (settled)
    mov  al, \v
    out  0x92, al
    .byte 0xEA
    .word 9f
    .word 0x1000
9:
.endm
.macro a20pm v
    mov  al, \v
    out  0x92, al
    .byte 0xEA
    .long 9f
    .word 0x08
9:
.endm
PT  = 0x21000
PT2 = 0x23000
.code16
.org 0x100
start:
    cli
    mov  ax, 0x1000
    mov  ss, ax
    mov  sp, 0xF000
    mov  dword ptr [logp], offset log
    xor  ax, ax
    mov  es, ax                     # 0000: the first 64 KB
    mov  ax, 0xFFFF
    mov  fs, ax                     # FFFF: FFFF0-10FFEF
    mov  dword ptr es:[0x500], 0x11111111
    mov  dword ptr fs:[0x510], 0x22222222          # 100500
    mov  dword ptr es:[0x504], 0x44444444
    mov  dword ptr fs:[0x514], 0x55555555          # 100504
    mov  eax, fs:[0x510]                            # (A20 enabled: 22222222)
    logr eax
    a20rm 2

    # ---- protected mode, paging (pm11's map)
    lgdt [gdtr]
    lidt [idtr]
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
    mov  esp, 0xF000
    mov  ax, 0x28
    mov  es, ax
    mov  fs, ax
    # directory 20000: 0-3FFFFF -> table 21000 (pages 0-3F identity), 400000-7FFFFF ->
    # 122000; 800000-BFFFFF not present (mapped by the #PF handler to table 23000)
    mov  edi, 0x20000
    mov  ecx, 3072
    xor  eax, eax
    cld
    rep  stosd
    mov  dword ptr es:[0x20000], PT + 7
    mov  dword ptr es:[0x20004], 0x122007
    mov  edi, PT
    mov  eax, 7
    mov  ecx, 0x40
1:  stosd
    add  eax, 0x1000
    loop 1b
    mov  dword ptr es:[PT + 0x40*4], 0x140007       # 40000 -> 140000
    mov  dword ptr es:[PT + 0x41*4], 0x040007       # 41000 -> 40000 (the masked twin)
    mov  dword ptr es:[PT + 0x42*4], 0x142007       # 42000 -> 142000
    mov  dword ptr es:[PT + 0x43*4], 0x042007       # 43000 -> 42000
    mov  dword ptr es:[PT + 0x3E*4], 0x122007       # 3E000 -> 122000
    mov  dword ptr es:[0x22000], 0x31007            # masked table: 400000 -> 31000
    mov  dword ptr es:[PT2], 0x32007                # 800000 -> 32000 (once the PDE is set)
    mov  dword ptr es:[0x32100], 0x32323232
    mov  eax, 0x20000
    mov  cr3, eax
    mov  eax, cr0
    or   eax, 0x80000000
    mov  cr0, eax
    jmp  1f
1:  mov  dword ptr fs:[0x3E000], 0x30007            # 400000 -> 30000 (table above 1 MB)
    mov  dword ptr fs:[0x40100], 0x77777777         # 140100
    mov  dword ptr fs:[0x41100], 0x88888888         # 040100
    mov  dword ptr fs:[0x42100], 0xAAAAAAAA         # 142100
    mov  dword ptr fs:[0x43100], 0xBBBBBBBB         # 042100
    # ---- #PF from a not-present directory entry
    mov  eax, fs:[0x800100]                         # #PF (PDE), mapped, restarted: 32323232
    logr eax
    # ---- INVLPG / CR3 writes while the L2 TLB clears
    mov  eax, fs:[0x400100]                         # (walk through 122000: 30100)
    mov  eax, cr3
    mov  cr3, eax
    invlpg fs:[0x400000]
    mov  cr3, eax
    mov  dword ptr fs:[0x3E000], 0x31007            # 400000 -> 31000 now
    mov  eax, cr3
    mov  cr3, eax
    invlpg fs:[0x40000]
    mov  eax, fs:[0x400100]                         # a new walk: 31100
    logr eax
    mov  eax, [logp]
    hlt

hpf:                                # #PF: log CR2 and the error code, map 800000-BFFFFF
    pop  eax
    logr eax
    mov  eax, cr2
    logr eax
    mov  dword ptr es:[0x20008], PT2 + 7
    iretd
hgp:                                # (not expected)
    mov  eax, [esp]
    or   eax, 0x0D0000
    logr eax
    hlt

.align 4
logp:   .long 0
log:    .fill 40, 4, 0
gdtr:   .word 0x37
        .long 0x10A00
idtr:   .word 0x0F * 8 - 1
        .long 0x10800
.org 0x800
idt:
    .fill 13, 8, 0
    gate hgp, 0x08, 0x8E                   # 13 #GP
    gate hpf, 0x08, 0x8E                   # 14 #PF
.org 0xA00
gdt:
    .quad 0
    desc 0x10000, 0xFFFF, 0x9A, 4          # 08 code32
    desc 0x10000, 0xFFFFF, 0x92, 0xC       # 10 data32
    .quad 0
    .quad 0
    desc 0, 0xFFFFF, 0x92, 0xC             # 28 flat data
    desc 0, 0xFFFFF, 0x9A, 0xC             # 30 flat code32
