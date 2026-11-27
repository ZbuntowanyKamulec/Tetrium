# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# UMOV (0F 10-13, undocumented): on the 386 / 486 outside ICE mode an alias of MOV r/m, r
# (0F 10 / 11) and MOV r, r/m (0F 12 / 13), byte and word / dword, register and memory forms.
.intel_syntax noprefix
.code16
.org 0x100
start:
    cli
    mov  eax, 0x11223344
    mov  ecx, 0x55667788
    .byte 0x0F, 0x10, 0xC3          # umov bl, al
    .byte 0x0F, 0x11, 0xCA          # umov dx, cx
    .byte 0x66, 0x0F, 0x11, 0xC6    # umov esi, eax
    .byte 0x0F, 0x12, 0xF9          # umov bh, cl
    .byte 0x66, 0x0F, 0x13, 0xF9    # umov edi, ecx
    .byte 0x0F, 0x10, 0x06          # umov [m], al
    .word m
    .byte 0x66, 0x0F, 0x11, 0x0E    # umov [m + 4], ecx
    .word m + 4
    .byte 0x0F, 0x11, 0x06          # umov [m + 8], ax
    .word m + 8
    .byte 0x0F, 0x12, 0x2E          # umov ch, [m + 5]
    .word m + 5
    .byte 0x66, 0x0F, 0x13, 0x16    # umov edx, [m + 4]
    .word m + 4
    .byte 0x0F, 0x13, 0x2E          # umov bp, [m + 8]
    .word m + 8
    hlt
.align 4
m:  .fill 4, 4, 0
