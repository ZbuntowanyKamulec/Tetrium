# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Paths the RTL coverage report (tools/vcov.py) found unused, in real mode with INTR every N
# cycles (lockirq, vector 8): HLT woken by INTR (IF set; DOS idles this way); a load right
# behind a store that crosses a dword boundary, from the store's second word (forwarded
# from E); a load from uncached (write-combining, B0000h) memory right behind a store that
# covers part of it; code fetched from that uncached memory (a routine copied to B000:0100,
# called, patched in place and called again, interrupted while it runs).
# The handler counts the interrupts; the results go to a log (compared store by store).
# lockirq: 97 301 733
.intel_syntax noprefix
.macro logr r                       # append a register to the log
    mov  di, [logp]
    mov  [di], \r
    add  word ptr [logp], 4
.endm
.code16
.org 0x100
start:
    cli
    xor  ax, ax
    mov  es, ax
    mov  word ptr es:[0x20], offset hirq      # vector 8 (the testbench's INTR)
    mov  word ptr es:[0x22], 0x1000
    mov  ax, 0x2000
    mov  ss, ax
    mov  sp, 0xFFF0
    mov  word ptr [logp], offset log
    mov  dword ptr [nirq], 0
# ---- HLT, woken by INTR
    sti
    mov  cx, 12
1:  hlt
    loop 1b
    mov  eax, [nirq]
    logr eax
# ---- the second word of a dword-crossing store, loaded right after it
    mov  bx, offset buf
    mov  eax, 0x11223344
    mov  si, 1
2:  mov  [bx + si], eax                         # bytes si .. si+3: crosses into buf+4
    mov  cl, [bx + 4]
    mov  [bx + si + 8], eax
    mov  dx, [bx + 12]
    mov  [bx + si + 16], eax
    mov  edx, [bx + 20]
    logr ecx
    logr edx
    add  eax, 0x01010101
    inc  si
    cmp  si, 4
    jb   2b
    mov  dword ptr [bx + 24], 0xA5A5A5A5
    mov  word ptr [bx + 27], 0x7788             # bytes 27, 28
    mov  eax, [bx + 28]
    logr eax
# ---- uncached memory: a load partly covered by the store before it
    mov  ax, 0xB000
    mov  es, ax
    mov  dword ptr es:[0x10], 0xCAFEBABE
    mov  dword ptr es:[0x14], 0x01234567
    mov  word ptr es:[0x10], 0x5566
    mov  ecx, es:[0x10]                         # 2 bytes from the store, 2 from memory
    logr ecx
    mov  byte ptr es:[0x13], 0x99
    mov  ecx, es:[0x12]                         # store byte 13, memory 12, 14, 15
    logr ecx
    mov  dword ptr es:[0x12], 0x0BADF00D        # crosses into 14
    mov  ecx, es:[0x14]
    logr ecx
    mov  cx, es:[0x11]
    logr ecx
# ---- code in uncached memory
    mov  si, offset rtn
    mov  di, 0x100
    mov  cx, rtn_end - rtn
    cld
    rep  movsb                                  # DS:SI -> ES:DI = B000:0100
    xor  eax, eax
    .byte 0x9A                                  # CALL FAR B000:0100
    .word 0x100, 0xB000
    logr eax
    mov  byte ptr es:[0x100 + rtn_imm - rtn], 7 # patch the routine's immediate
    .byte 0x9A
    .word 0x100, 0xB000
    logr eax
    mov  cx, 20
3:  push cx
    .byte 0x9A
    .word 0x100, 0xB000
    pop  cx
    loop 3b
    logr eax
    cli
    mov  eax, [nirq]
    logr eax
    mov  ax, [logp]
    hlt

rtn:                                            # (position-independent: copied to B000:0100)
    mov  cx, 40
1:  .byte 0x66, 0x83, 0xC0                       # add eax, imm8
rtn_imm:
    .byte 3
    test cx, 1
    jz   2f
    xor  eax, 0x55
2:  loop 1b
    retf
rtn_end:

hirq:
    inc  dword ptr cs:[nirq]
    iret

.align 4
nirq:   .long 0
logp:   .word 0, 0
buf:    .fill 32, 1, 0
log:    .fill 40, 4, 0
