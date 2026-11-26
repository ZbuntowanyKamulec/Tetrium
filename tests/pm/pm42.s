# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Data breakpoints with the A20 gate closed (real mode): the 486 compares DRn with the linear
# address, A20M# masks only the physical one.  FFFF:0510 (linear 100500h, physical 000500h)
# must match DR0 = 100500h and not DR0 = 000500h; a dword at FFFF:000E (FFFFEh .. 100001h)
# reaches its second word through the wrap: DR0 = 100000h / 100001h match, 000000h / 000001h
# not.  Loads and stores (a crossing store writes back what was read), then a check with the
# gate open.  DR6 after each access and the #DB count go to the log.
.intel_syntax noprefix
.macro logr r                       # append a register to the log
    mov  ebx, [logp]
    mov  [ebx], \r
    add  dword ptr [logp], 4
.endm
.macro a20 v                        # set the gate, far jump (settled)
    mov  al, \v
    out  0x92, al
    .byte 0xEA
    .word 9f
    .word 0x1000
9:
.endm
.macro bp addr                      # DR0 = addr, byte, read / write, L0; DR6 cleared
    mov  eax, \addr
    mov  dr0, eax
    mov  eax, 0x00030001
    mov  dr7, eax
    xor  eax, eax
    mov  dr6, eax
.endm
.macro res                          # log DR6, clear it
    mov  eax, dr6
    logr eax
    xor  eax, eax
    mov  dr6, eax
.endm
.code16
.org 0x100
start:
    cli
    mov  ax, 0x1000
    mov  ss, ax
    mov  sp, 0xF000
    mov  dword ptr [logp], offset log
    mov  dword ptr [ndb], 0
    xor  ax, ax
    mov  es, ax
    mov  word ptr es:[4], offset hdb            # vector 1 (#DB)
    mov  word ptr es:[6], 0x1000
    mov  ax, 0xFFFF
    mov  fs, ax                     # FFFF: FFFF0-10FFEF
    a20  2
    mov  dword ptr es:[0x500], 0x11111111
    mov  dword ptr fs:[0x510], 0x22222222       # 100500
    a20  0
    # ---- one dword in the wrapped region: linear 100500h, physical 000500h
    bp   0x100500
    mov  eax, fs:[0x510]
    logr eax
    res
    bp   0x000500
    mov  eax, fs:[0x510]
    res
    bp   0x100500
    mov  dword ptr fs:[0x510], 0x33333333
    res
    bp   0x000500
    mov  dword ptr fs:[0x510], 0x44444444
    res
    # ---- a dword across 1 MB (FFFFEh .. 100001h): the second word through the wrap
    bp   0x100001
    mov  ecx, fs:[0x0E]
    logr ecx
    res
    bp   0x000001
    mov  ecx, fs:[0x0E]
    res
    bp   0x100000
    mov  fs:[0x0E], ecx                         # (writes back the same bytes)
    res
    bp   0x000000
    mov  fs:[0x0E], ecx
    res
    # ---- the gate open: linear = physical
    a20  2
    bp   0x100500
    mov  eax, fs:[0x510]
    logr eax
    res
    bp   0x000500
    mov  eax, fs:[0x510]
    res
    xor  eax, eax
    mov  dr7, eax
    mov  eax, [ndb]
    logr eax
    mov  eax, es:[0x500]
    logr eax
    mov  eax, [logp]
    hlt

hdb:                                # #DB (data breakpoint trap): count
    inc  dword ptr cs:[ndb]
    iret

.align 4
ndb:    .long 0
logp:   .long 0
log:    .fill 40, 4, 0
