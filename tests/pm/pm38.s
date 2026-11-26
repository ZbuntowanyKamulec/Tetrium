# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# Protected-mode descriptor checks the RTL coverage report (tools/vcov.py) found never failing:
# ring 0: LLDT null / not present, LTR not present, far JMP / CALL to a data segment, to
# non-conforming code of another DPL, to conforming code of a higher DPL, to a not-present
# segment, to a TSS with DPL < RPL, to the busy TSS, to a not-present TSS, through a task gate
# to a not-present TSS; MOV CR0 with NW without CD and PG without PE; MOV TR3-TR5 (TR3 reads
# the cache read buffer, TR4 / TR5 read back); INT to a
# not-present code segment; IRET / RETF with a null and a not-present CS.
# ring 3: RETF to a more privileged CS, INT to a not-present inner code segment, RETF to an
# outer stack that is not present; CALL through a gate with a null and a not-present inner
# SS (#TS / #SS through a task gate whose handler task fixes SS0, the CALL is retried); a
# TSS too short for the inner stack of a ring 2 call gate (#TS).  V86 (IOPL 3): INT to a
# ring 3 and to a ring 1 code segment (#GP).  Task switches (CALL to TSS B) whose new task
# has a not-present CS, an SS of the wrong DPL / not present, a data segment that is
# execute-only code / not present / of a lower DPL than its RPL, an EIP beyond its CS limit:
# the fault is taken in the new task, through a task gate to a handler task that repairs
# TSS B and points it at an IRETD back to the caller.
# The interrupt-gate handlers add vector and error code to [sum] and resume at ESI.
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
.macro jmpf sel, off
    .byte 0xEA
    .long \off
    .word \sel
.endm
.macro callf sel, off
    .byte 0x9A
    .long \off
    .word \sel
.endm
.macro igate v, off, acc           # IDT entry v = gate to 08:off
    mov  word ptr [idt + \v * 8], offset \off
    mov  word ptr [idt + \v * 8 + 2], 0x08
    mov  dword ptr [idt + \v * 8 + 4], (\acc) << 8
.endm
.macro tgate v, tss                # IDT entry v = task gate to TSS selector tss
    mov  dword ptr [idt + \v * 8], (\tss) << 16
    mov  dword ptr [idt + \v * 8 + 4], 0x8500
.endm
.macro ring3 entry, next           # IRETD to ring 3 at entry; INT 41h continues at next
    mov  dword ptr [cont], offset \next
    push 0x3B
    push 0xE000
    pushfd
    push 0x33
    push offset \entry
    iretd
.endm
TSSA = 0x1000
TSSB = 0x1080
TSSF = 0x1100
TSSG = 0x1180
TSSS = 0x1200
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
    mov  ax, 0x18
    ltr  ax
# ================================================================ ring 0
    xor  eax, eax
    lldt ax                                 # null LDT
    mov  ax, 0x48
    T lldt ax                               # not present: #NP(48)
    mov  ax, 0x50
    T ltr ax                                # not present: #NP(50)
    T jmpf 0x10, 0                          # data segment: #GP(10)
    T jmpf 0x30, 0                          # non-conforming DPL 3: #GP(30)
    T callf 0xB0, 0                         # conforming DPL 3 > CPL: #GP(B0)
    T jmpf 0x60, 0                          # not present: #NP(60)
    T jmpf 0x5B, 0                          # TSS B, RPL 3 > DPL: #GP(58)
    T jmpf 0x18, 0                          # the busy TSS A: #GP(18)
    T jmpf 0x50, 0                          # not-present TSS: #NP(50)
    T jmpf 0xA0, 0                          # task gate -> not-present TSS: #NP(50)
    mov  eax, cr0
    mov  ecx, eax
    and  ecx, 0xBFFFFFFF                    # CD = 0
    or   ecx, 0x20000000                    # NW = 1
    T mov cr0, ecx                          # #GP(0)
    mov  ecx, eax
    and  ecx, 0xFFFFFFFE                    # PE = 0
    or   ecx, 0x80000000                    # PG = 1
    T mov cr0, ecx                          # #GP(0)
    mov  eax, 0x12345678
    mov  tr3, eax
    mov  eax, 0x9ABCDEF0
    mov  tr4, eax
    mov  eax, 0x0F1E2D3C
    mov  tr5, eax
    mov  ecx, tr3                           # the cache read buffer (no cache read yet): 0
    add  [sum], ecx
    mov  eax, 0x00000008                    # TR5: ENT 2
    mov  tr5, eax
    mov  eax, 0x13572468
    mov  tr3, eax                           # fill buffer doubleword 2
    mov  ecx, tr3                           # read buffer doubleword 2: 0
    add  [sum], ecx
    mov  ecx, tr4
    add  [sum], ecx
    mov  ecx, tr5
    add  [sum], ecx
    T int 0x43                              # gate -> not-present code (same level): #NP(60)
    pushfd
    push 0                                  # IRETD with a null CS: #GP(0)
    push offset 1f
    T iretd
    add  esp, 12
    pushfd
    push 0x60                               # IRETD to a not-present CS: #NP(60)
    push offset 1f
    T iretd
    add  esp, 12
    push 0
    push offset 1f
    T retf                                  # RETF with a null CS: #GP(0)
    add  esp, 8
    push 0x60
    push offset 1f
    T retf                                  # RETF to a not-present CS: #NP(60)
    add  esp, 8
1:
# ================================================================ ring 3
    ring3 r3a, p2
r3a:
    mov  ax, 0x3B
    mov  ds, ax
    mov  es, ax
    push 0x08
    push offset 1f
    T retf                                  # to RPL 0 from CPL 3: #GP(08)
    add  esp, 8
1:  T int 0x42                              # gate -> not-present ring 0 code: #NP(60)
    callf 0x8B, 0                           # to ring 0 (g_r0): RETF to a not-present outer SS
    int  0x41
g_r0:                                       # ring 0, through the call gate from ring 3
    mov  dword ptr [esp + 12], 0x7B         # the outer SS: not present
    T retf                                  # #SS(78)
    mov  dword ptr [esp + 12], 0x3B
    retf
g_ret:                                      # ring 0, through a call gate: back at once
    retf
# ---- inner stack from the TSS: null, not present (#TS / #SS through task gates to task G)
p2: tgate 10, 0xB8
    tgate 12, 0xB8
    mov  word ptr [TSSA + 8], 0             # SS0 null
    ring3 r3b, p3
r3b:
    mov  ax, 0x3B
    mov  ds, ax
    callf 0xCB, 0                           # #TS(0): G sets SS0, the CALL is retried
    mov  word ptr [TSSA + 8], 0x80          # SS0 not present
    callf 0xCB, 0                           # #SS(80): the same
    int  0x41
# ---- a TSS too short for the inner stack of a ring 2 call gate (#TS)
p3: igate 10, h10, 0x8E
    igate 12, h12, 0x8E
    mov  byte ptr [gdt + 0x18 + 5], 0x89    # TSS A: available again
    mov  ax, 0x70
    ltr  ax                                 # TSS S: limit 17h (SS0:ESP0 only)
    ring3 r3c, p4
r3c:
    mov  ax, 0x3B
    mov  ds, ax
    T callf 0x9B, 0                         # ring 2 gate: SS2 beyond the TSS limit: #TS(70)
    int  0x41
# ---- V86: INT to code segments a V86 task may not enter (#GP)
p4: mov  byte ptr [gdt + 0x70 + 5], 0x89
    mov  ax, 0x18
    ltr  ax
    mov  dword ptr [cont], offset p5
    push 0x1000                             # GS
    push 0x1000                             # FS
    push 0x1000                             # DS
    push 0x1000                             # ES
    push 0x2000                             # SS
    push 0xFFF0                             # SP
    push 0x00023002                         # EFLAGS: VM, IOPL 3
    push 0x1000                             # CS
    push offset v86
    iretd
.code16
v86:
    T int 0x44                              # -> ring 3 code: #GP(30)
    T int 0x45                              # -> ring 1 code: #GP(C0)
    int  0x41
.code32
# ---- task switches whose new task faults (handler task F repairs TSS B)
p5: tgate 10, 0x68
    tgate 11, 0x68
    tgate 12, 0x68
    tgate 13, 0x68
    call resetb
    mov  dword ptr [TSSB + 0x4C], 0x60      # CS not present: #NP(60)
    callf 0x58, 0
    call resetb
    mov  dword ptr [TSSB + 0x50], 0x3B      # SS of DPL 3 for CPL 0: #TS(38)
    callf 0x58, 0
    call resetb
    mov  dword ptr [TSSB + 0x50], 0x80      # SS not present: #SS(80)
    callf 0x58, 0
    call resetb
    mov  dword ptr [TSSB + 0x54], 0xD8      # DS execute-only code: #TS(D8)
    callf 0x58, 0
    call resetb
    mov  dword ptr [TSSB + 0x54], 0x80      # DS not present: #NP(80)
    callf 0x58, 0
    call resetb
    mov  dword ptr [TSSB + 0x48], 0x13      # ES RPL 3 > DPL 0: #TS(10)
    callf 0x58, 0
    call resetb
    mov  dword ptr [TSSB + 0x20], 0x20000   # EIP beyond the CS limit
    callf 0x58, 0
    mov  eax, [sum]
    hlt
resetb:                                     # TSS B: a valid task at b_ret
    mov  dword ptr [TSSB + 0x20], offset b_ret
    mov  dword ptr [TSSB + 0x24], 0x4002    # (NT: the repaired task still returns to A)
    mov  dword ptr [TSSB + 0x38], 0xC000
    mov  dword ptr [TSSB + 0x48], 0x10
    mov  dword ptr [TSSB + 0x4C], 0x08
    mov  dword ptr [TSSB + 0x50], 0x10
    mov  dword ptr [TSSB + 0x54], 0x10
    mov  dword ptr [TSSB + 0x58], 0x10
    mov  dword ptr [TSSB + 0x5C], 0x10
    mov  dword ptr [TSSB + 0x60], 0
    ret
b_ret:                                      # task B: back to the caller (NT)
    add  dword ptr [sum], 0x5000
    iretd
f_task:                                     # task F: the new task faulted; repair TSS B
    pop  eax
    add  [sum], eax
    call resetb
    iretd
    jmp  f_task
g_task:                                     # task G: the inner stack faulted; SS0 = 10
    pop  eax
    add  [sum], eax
    mov  word ptr [TSSA + 8], 0x10
    iretd
    jmp  g_task
# ---- interrupt-gate handlers (ring 0): log vector and error code, resume at ESI
h10: push 10
     jmp  hc
h11: push 11
     jmp  hc
h12: push 12
     jmp  hc
h13: push 13
     jmp  hc
hc:  pop  eax
     pop  ebx
     shl  eax, 16
     add  ss:[sum], eax
     add  ss:[sum], ebx
     mov  [esp], esi
     iretd
h06: add  dword ptr ss:[sum], 0x60000   # (#UD: not expected)
     mov  [esp], esi
     iretd
h41: mov  ax, 0x10                      # INT 41h from ring 3 / V86: continue at ring 0
     mov  ds, ax
     mov  es, ax
     mov  fs, ax
     mov  gs, ax
     mov  ss, ax
     mov  esp, 0xF000
     jmp  dword ptr [cont]
g_r2:                                   # ring 2 (never reached: the stack switch faults)
     retf
.align 4
sum:    .long 0
cont:   .long 0
gdtr:   .word 0xDF
        .long 0x11400
idtr:   .word 0x46 * 8 - 1
        .long 0x11800
.org TSSA
        .long 0, 0xF000, 0x10           # link, ESP0, SS0
        .fill 0x68 - 12, 1, 0
.org TSSB
        .fill 0x68, 1, 0
.org TSSF
        .long 0, 0, 0, 0, 0, 0, 0, 0
        .long f_task, 0x0002
        .long 0, 0, 0, 0, 0xA000, 0, 0, 0
        .long 0x10, 0x08, 0x10, 0x10, 0x10, 0x10, 0
        .long 0
.org TSSG
        .long 0, 0, 0, 0, 0, 0, 0, 0
        .long g_task, 0x0002
        .long 0, 0, 0, 0, 0xB000, 0, 0, 0
        .long 0x10, 0x08, 0x10, 0x10, 0x10, 0x10, 0
        .long 0
.org TSSS
        .long 0, 0xF000, 0x10, 0, 0, 0
.org 0x1400
gdt:
    .quad 0
    desc 0x10000, 0xFFFF, 0x9A, 4          # 08 code32
    desc 0x10000, 0xFFFFF, 0x92, 0xC       # 10 data32
    desc 0x11000, 0x67, 0x89, 0            # 18 TSS A
    desc 0x10000, 0xFFFF, 0x9A, 0          # 20 code16
    desc 0x10000, 0xFFFF, 0x9E, 4          # 28 code32 conforming
    desc 0x10000, 0xFFFF, 0xFA, 4          # 30 code32 ring 3
    desc 0x10000, 0xFFFFF, 0xF2, 0xC       # 38 data32 ring 3
    .quad 0                                # 40
    desc 0x11300, 0x07, 0x02, 0            # 48 LDT, not present
    desc 0x11280, 0x67, 0x09, 0            # 50 TSS, not present
    desc 0x11080, 0x67, 0x89, 0            # 58 TSS B
    desc 0x10000, 0xFFFF, 0x1A, 4          # 60 code32, not present
    desc 0x11100, 0x67, 0x89, 0            # 68 TSS F
    desc 0x11200, 0x17, 0x89, 0            # 70 TSS S (short)
    desc 0x10000, 0xFFFFF, 0x72, 0xC       # 78 data32 ring 3, not present
    desc 0x10000, 0xFFFFF, 0x12, 0xC       # 80 data32, not present
    gate g_r0, 0x08, 0xEC                  # 88 call gate DPL 3 -> ring 0 (g_r0)
    desc 0x10000, 0xFFFF, 0xDA, 4          # 90 code32 ring 2
    gate g_r2, 0x90, 0xEC                  # 98 call gate DPL 3 -> ring 2
    gate 0, 0x50, 0x85                     # A0 task gate -> not-present TSS
    .quad 0                                # A8
    desc 0x10000, 0xFFFF, 0xFE, 4          # B0 code32 conforming, DPL 3
    desc 0x11180, 0x67, 0x89, 0            # B8 TSS G
    desc 0x10000, 0xFFFF, 0xBA, 4          # C0 code32 ring 1
    gate g_ret, 0x08, 0xEC                 # C8 call gate DPL 3 -> ring 0 (g_ret)
    .quad 0                                # D0
    desc 0x10000, 0xFFFF, 0x98, 4          # D8 code32 execute-only
.org 0x1800
idt:
    .fill 6, 8, 0
    gate h06, 0x08, 0x8E                   # 06
    .fill 3, 8, 0
    gate h10, 0x08, 0x8E                   # 0A
    gate h11, 0x08, 0x8E                   # 0B
    gate h12, 0x08, 0x8E                   # 0C
    gate h13, 0x08, 0x8E                   # 0D
    .fill 0x41 - 14, 8, 0
    gate h41, 0x08, 0xEE                   # 41 (DPL 3)
    gate 0, 0x60, 0xEE                     # 42 -> not-present code (DPL 3 gate)
    gate 0, 0x60, 0x8E                     # 43 -> not-present code
    gate 0, 0x30, 0xEE                     # 44 -> ring 3 code
    gate 0, 0xC0, 0xEE                     # 45 -> ring 1 code
