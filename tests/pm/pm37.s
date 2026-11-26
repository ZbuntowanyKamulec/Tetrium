# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Microcode entries the coverage report (tools/ucov.py) found never run: the register forms
# that raise #UD (0F 01 /0-3 /7, LES / LDS, LSS / LFS / LGS, CALL / JMP FAR r) in real mode
# and at 32-bit ring 0; JMP FAR through call gates (32- and 16-bit gates, direct and through
# memory; not present, a data segment or a not-present code segment as target; from ring 3
# to conforming ring 0 code, to non-conforming ring 0 code and through a DPL 0 gate); then
# exceptions with an error code through IDT task gates (#GP to a 386 TSS, #NP to a 286 TSS:
# the error code pushed on the new task's stack; the handler task fixes the faulting
# selector in the old task's TSS and IRETs back, the instruction restarts).
# The handlers resume after the instruction (ESI / SI).  The image is loaded at 1000:0000.
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
.macro T insn:vararg
    mov  esi, offset 9f
    \insn
9:
.endm
.macro jmpf sel, off                 # JMP FAR sel:off (32-bit code)
    .byte 0xEA
    .long \off
    .word \sel
.endm
# the #UD register forms (mod = 3)
.macro udforms
    T .byte 0x0F, 0x01, 0xC1         # SGDT r
    T .byte 0x0F, 0x01, 0xCA         # SIDT r
    T .byte 0x0F, 0x01, 0xD3         # LGDT r
    T .byte 0x0F, 0x01, 0xDC         # LIDT r
    T .byte 0x0F, 0x01, 0xFD         # INVLPG r
    T .byte 0xC4, 0xC0               # LES r
    T .byte 0xC5, 0xD9               # LDS r
    T .byte 0x0F, 0xB2, 0xC2         # LSS r
    T .byte 0x0F, 0xB4, 0xCB         # LFS r
    T .byte 0x0F, 0xB5, 0xD6         # LGS r
    T .byte 0xFF, 0xD8               # CALL FAR r
    T .byte 0xFF, 0xEB               # JMP FAR r
.endm
.code16
.org 0x100
start:
    cli
    push ds
    xor  ax, ax
    mov  ds, ax
    mov  word ptr [6 * 4], offset ud_rm
    mov  word ptr [6 * 4 + 2], cs
    pop  ds
    mov  ax, 0x2000
    mov  ss, ax
    mov  sp, 0xFFF0
# ---- real mode
    udforms
    lgdt [gdtr]
    lidt [idtr]
    mov  eax, cr0
    or   al, 1
    mov  cr0, eax
    .byte 0x66, 0xEA
    .long pm32
    .word 0x08
ud_rm:
    push bp
    mov  bp, sp
    mov  [bp + 2], si
    pop  bp
    iret
.code32
pm32:
    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  ss, ax
    mov  esp, 0xF000
    mov  ax, 0x18
    ltr  ax
# ---- 32-bit ring 0
    udforms
    jmpf 0x40, 0                     # 32-bit call gate -> 08:jg32
back1:
    jmpf 0x48, 0                     # 16-bit call gate -> 20:jg16
back2:
    .byte 0xFF, 0x2D                 # JMP FAR [fp]: through the 32-bit gate again
    .long fp
back3:
    T jmpf 0x50, 0                   # gate not present: #NP(50)
    T jmpf 0x58, 0                   # gate to a data segment: #GP(10)
    T jmpf 0x68, 0                   # gate to a not-present code segment: #NP(60)
# ---- ring 3
    push 0x3B                        # SS
    push 0xE000                      # ESP
    pushfd
    push 0x33                        # CS
    push offset r3
    iretd
jg32:
    add  dword ptr [sum], 0x100
    cmp  dword ptr [sum], 0x200
    jae  back3
    jmp  back1
jconf:                               # (conforming code: CPL stays 3)
    add  dword ptr [sum], 0x400
    jmpf 0x33, r3b
r3:
    mov  ax, 0x3B
    mov  ds, ax
    mov  es, ax
    jmpf 0x73, 0                     # DPL 3 gate -> conforming ring 0 code
r3b:
    T jmpf 0x7B, 0                   # DPL 3 gate -> non-conforming ring 0 code: #GP(08)
    T jmpf 0x43, 0                   # DPL 0 gate: #GP(40)
    int  0x41                        # back to ring 0
# ---- exceptions with an error code through task gates
done3:
    mov  ax, 0x10
    mov  ds, ax
    mov  es, ax
    mov  dword ptr [idt + 13 * 8], 0x00800000      # #GP -> task gate, TSS G (386)
    mov  dword ptr [idt + 13 * 8 + 4], 0x00008500
    mov  dword ptr [idt + 11 * 8], 0x00880000      # #NP -> task gate, TSS H (286)
    mov  dword ptr [idt + 11 * 8 + 4], 0x00008500
    mov  ebx, 0xF8                   # beyond the GDT limit: #GP(F8)
    mov  ds, bx
    mov  ebx, 0x90                   # not present: #NP(90)
    mov  ds, bx
    mov  ebx, 0xF8                   # the task G again (EIP after its IRET: the JMP back)
    mov  ds, bx
    mov  eax, [sum]
    hlt
# ring 0 handlers (32-bit interrupt gates): log, resume at ESI
h_ud:
    add  dword ptr ss:[sum], 6
    mov  [esp], esi
    iretd
h_np:
    pop  eax
    add  dword ptr ss:[sum], eax
    add  dword ptr ss:[sum], 0x1100
    mov  [esp], esi
    iretd
h_gp:
    pop  eax
    add  dword ptr ss:[sum], eax
    add  dword ptr ss:[sum], 0x1300
    mov  [esp], esi
    iretd
gtask:                               # 386 task G: #GP
    pop  eax
    add  [sum], eax
    mov  dword ptr [tssA + 0x34], 0x10    # the old task's EBX: a valid selector
    iretd
    jmp  gtask
.code16
jg16:
    add  dword ptr [sum], 0x10
    .byte 0x66, 0xEA
    .long back2
    .word 0x08
htask:                               # 286 task H: #NP
    pop  ax
    add  [sum], ax
    mov  dword ptr [tssA + 0x34], 0x10
    iret
    jmp  htask
.code32
.align 4
sum:    .long 0
fp:     .long 0
        .word 0x40
gdtr:   .word 0x9F
        .long 0x10800
idtr:   .word 0x42 * 8 - 1
        .long 0x10C00
.org 0x600
tssA:   .long 0, 0xF000, 0x10                      # link, ESP0, SS0
        .fill 0x68 - 12, 1, 0
.org 0x680
tssG:   .long 0, 0, 0, 0, 0, 0, 0, 0               # link, ESP0, SS0 ... CR3 (0)
        .long gtask, 0x0002                        # EIP, EFLAGS
        .long 0x11, 0x22, 0x33, 0x44, 0xD000, 0x66, 0x77, 0x88
        .long 0x10, 0x08, 0x10, 0x10, 0, 0, 0      # ES CS SS DS FS GS LDT
        .long 0
.org 0x700
tssH:   .word 0, 0, 0, 0, 0, 0, 0                  # link, SP0 SS0 .. SP2 SS2
        .word htask, 0x0002                        # IP, FLAGS
        .word 1, 2, 3, 4, 0xC000, 6, 7, 8
        .word 0x10, 0x20, 0x98, 0x10, 0            # ES CS SS DS LDT
.org 0x800
gdt:
    .quad 0
    desc 0x10000, 0xFFFF, 0x9A, 4          # 08 code32
    desc 0x10000, 0xFFFFF, 0x92, 0xC       # 10 data32
    desc 0x10600, 0x67, 0x89, 0            # 18 TSS A
    desc 0x10000, 0xFFFF, 0x9A, 0          # 20 code16
    desc 0x10000, 0xFFFF, 0x9E, 4          # 28 code32, conforming
    desc 0x10000, 0xFFFF, 0xFA, 4          # 30 code32, ring 3
    desc 0x10000, 0xFFFFF, 0xF2, 0xC       # 38 data32, ring 3
    gate jg32, 0x08, 0x8C                  # 40 call gate 32 -> 08:jg32
    gate jg16, 0x20, 0x84                  # 48 call gate 16 -> 20:jg16
    gate jg32, 0x08, 0x0C                  # 50 call gate, not present
    gate 0, 0x10, 0x8C                     # 58 call gate -> data segment
    desc 0x10000, 0xFFFF, 0x1A, 4          # 60 code32, not present
    gate 0, 0x60, 0x8C                     # 68 call gate -> 60
    gate jconf, 0x28, 0xEC                 # 70 call gate DPL 3 -> conforming
    gate jg32, 0x08, 0xEC                  # 78 call gate DPL 3 -> 08 (DPL 0)
    desc 0x10680, 0x67, 0x89, 0            # 80 TSS G (386)
    desc 0x10700, 0x2B, 0x81, 0            # 88 TSS H (286)
    desc 0x10000, 0xFFFF, 0x12, 0          # 90 data, not present
    desc 0x40000, 0xFFFF, 0x92, 0          # 98 16-bit stack
.org 0xC00
idt:
    .fill 6, 8, 0
    gate h_ud, 0x08, 0x8E                  # 06
    .fill 4, 8, 0
    gate h_np, 0x08, 0x8E                  # 0B
    .fill 1, 8, 0
    gate h_gp, 0x08, 0x8E                  # 0D
    .fill 0x41 - 14, 8, 0
    gate done3, 0x08, 0xEE                 # 41 (DPL 3)
