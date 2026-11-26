# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Self-modifying stores whose bytes span two cache lines (the I-cache looks the second line
# up in W, one cycle later): routines that sit across a 32-byte line boundary, already in the
# I-cache, patched by a dword store (the new immediate's low byte in the next line) and by a
# word store (the immediate split over the two lines), then called; misaligned REP MOVSW /
# MOVSD over a routine copy, called after each copy.  Sums of the results go to the log.
.intel_syntax noprefix
.macro logr r                       # append a register to the log
    mov  bx, [logp]
    mov  [bx], \r
    add  word ptr [logp], 4
.endm
.code16
.org 0x100
start:
    cli
    mov  ax, 0x1000
    mov  ss, ax
    mov  sp, 0xF000
    push cs
    pop  es
    mov  word ptr [logp], offset log
    cld
# ---- 1: dword store at line end - 2: bytes {90 90 | B8 imm.lo}, the imm.lo in the next line
    xor  edx, edx
    mov  cx, 300
1:  mov  eax, ecx
    shl  eax, 24
    or   eax, 0x00B89090            # {90 90 B8 cl}
    mov  dword ptr [r1 - 2], eax
    call r1 - 2
    add  edx, eax
    loop 1b
    logr edx
# ---- 2: word store across the boundary: the immediate's two bytes in two lines
    xor  edx, edx
    mov  cx, 300
2:  mov  ax, cx
    xor  ax, 0x5A3C
    mov  word ptr [r2 - 1], ax
    call r2 - 2
    add  edx, eax
    loop 2b
    logr edx
# ---- 3: REP MOVSW / MOVSD to an odd address: a routine copy across lines, called each time
    xor  edx, edx
    mov  cx, 40
3:  push cx
    mov  word ptr [src + 1], cx     # mov ax, imm16 = cx
    mov  si, offset src
    mov  di, offset r3 - 5
    mov  cx, 6
    rep  movsw
    call r3 - 5
    pop  cx
    push cx
    add  edx, eax
    xor  word ptr [src + 1], 0x1111
    mov  si, offset src
    mov  di, offset r3 - 5
    mov  cx, 3
    rep  movsd
    call r3 - 5
    pop  cx
    add  edx, eax
    loop 3b
    logr edx
    mov  ax, [logp]
    hlt

src:    .byte 0xB8, 0, 0            # mov ax, imm16
        .byte 0x83, 0xC0, 0x01      # add ax, 1
        .byte 0x83, 0xC0, 0x02      # add ax, 2
        .byte 0xC3                  # ret
        .byte 0x90, 0x90, 0x90
.align 4
logp:   .word 0, 0
log:    .fill 8, 4, 0

.balign 32
        .fill 32, 1, 0x90
# r1 - 2: 90 90 | B8 lo hi C3        (the line boundary at r1)
r1:     .byte 0xB8, 0x00, 0x00, 0xC3, 0xCC, 0xCC
.balign 32
        .fill 30, 1, 0x90
# r2 - 2: B8 lo | hi C3
        .byte 0xB8, 0x00
r2:     .byte 0x00, 0xC3, 0xCC, 0xCC
.balign 32
        .fill 32, 1, 0x90
r3:     .fill 32, 1, 0xCC
