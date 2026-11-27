# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Far CALL to an EIP beyond the target code segment's limit: #GP(0), and the 486 has already
# pushed the old CS and EIP (SDM Vol. 3 22.31.3: the pushes below ESP stay; ESP is restored).
# CALL ptr16:32, CALL m16:32, CALL ptr16:16, a same-privilege call gate (the lockstep compares
# the CALL's stores; the #GP frame then overwrites them); the handler logs the error code and ESP.
.intel_syntax noprefix
.macro desc base, limit, acc, fl
    .word (\limit) & 0xFFFF
    .word (\base) & 0xFFFF
    .byte ((\base) >> 16) & 0xFF
    .byte \acc
    .byte (((\limit) >> 16) & 0x0F) | ((\fl) << 4)
    .byte ((\base) >> 24) & 0xFF
.endm
.macro gate off, sel, acc        # (offsets below 64 KB)
    .word \off
    .word \sel
    .byte 0, \acc
    .word 0
.endm
.macro try lbl                      # the next instruction faults: resume at lbl
    mov  dword ptr [resume], offset \lbl
.endm
.code16
.org 0x100
start:
    cli
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
    mov  es, ax
    mov  ss, ax
    mov  esp, 0xF000
    mov  edi, offset log
    try  1f
    .byte 0x9A                      # call 0x18:0x2000 (limit 0FFF)
    .long 0x2000
    .word 0x18
1:  try  2f
    call fword ptr [fptr]           # call m16:32, the same target
2:  try  3f
    .byte 0x66, 0x9A                # call 0x18:0x1800, 16-bit operand
    .word 0x1800
    .word 0x18
3:  try  4f
    .byte 0x9A                      # call gate 0x20 (DPL 0, target 0x18:0x3000)
    .long 0
    .word 0x20
4:  hlt
hgp:
    pop  eax                        # error code
    stosd
    mov  eax, esp
    stosd
    mov  eax, [resume]
    mov  [esp], eax
    iretd
.align 4
resume: .long 0
fptr:   .long 0x2000
        .word 0x18
gdtr:   .word 0x27
        .long 0x10A00
idtr:   .word 14 * 8 - 1
        .long 0x10800
log:    .fill 16, 4, 0
.org 0x800
idt:
    .fill 13, 8, 0
    gate hgp, 0x08, 0x8E                           # 13 #GP
.org 0xA00
gdt:
    .quad 0
    desc 0x10000, 0xFFFF, 0x9A, 4          # 08 code32
    desc 0x10000, 0xFFFFF, 0x92, 0xC       # 10 data32 4 GB
    desc 0x10000, 0x0FFF, 0x9A, 4          # 18 code32, limit 0FFF
    gate 0x3000, 0x18, 0x8C                # 20 32-bit call gate, DPL 0
