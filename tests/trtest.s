# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
# TRTEST.COM: the i486 cache test registers TR3-TR5 on a real machine (DOS, real mode; not
# under EMM386 / V86).  With CR0.CD set (no new fills, hits still served):
#   1. TR4 written and read back
#   2. a 16-byte line for one of the program's own buffers written into the cache through
#      TR3 (fill buffer), TR4 (tag, valid) and TR5 (cache write, set of the buffer, way 0)
#   3. that line read back through TR5 (cache read) into TR4 and the read buffer (TR3)
#   4. the buffer loaded normally: a real i486 hits the injected line (cache-as-RAM) and
#      returns its data, not memory
#   5. TR5 cache flush, the buffer loaded again: memory
# Tetrium does not model the test-cache operations (TR3 reads 0, loads return memory);
# 86Box keeps a test-cache array of its own and also writes valid lines to memory.
# Output: DOS (INT 21h) on the screen; without DOS (the testbench: no INT 21h vector) on
# port E9h, then HLT.   Build: as --32 -o t.o tests/trtest.s && objcopy -O binary t.o t.bin &&
# tail -c +257 t.bin > TRTEST.COM  (the .org 0x100 pad is not part of a .COM file)
.intel_syntax noprefix
.code16
.org 0x100
start:
    xor  ax, ax
    mov  es, ax
    mov  ax, es:[0x21 * 4 + 2]
    mov  [dos], ax                      # INT 21h vector segment: 0 = no DOS
    push cs
    pop  es
    smsw ax
    test al, 1
    jz   1f
    mov  si, offset s_v86
    call puts
    jmp  quit
1:  mov  si, offset s_hdr
    call puts
    # the buffer's physical address, cache set and tag
    xor  eax, eax
    mov  ax, cs
    shl  eax, 4
    add  eax, offset buf
    mov  [pa], eax
    mov  ebx, eax
    and  ebx, 0x7F0                     # SET field (TR5 bits 10-4) = address bits 10-4
    mov  [setf], ebx
    and  eax, 0xFFFFF800                # tag = address bits 31-11
    mov  [tag], eax
    cli
    mov  eax, cr0
    mov  [cr0s], eax
    or   eax, 0x40000000                # CD = 1, NW = 0
    and  eax, 0xDFFFFFFF
    mov  cr0, eax
    wbinvd
    # ---- 1. TR4 read back
    mov  eax, 0x12345400
    mov  tr4, eax
    xor  eax, eax
    mov  tr5, eax
    mov  eax, tr4
    mov  [r_tr4a], eax
    # ---- 2. fill buffer (TR5 CTL 00, ENT = doubleword), tag + valid, cache write (way 0)
    xor  cx, cx
2:  mov  eax, [setf]
    movzx edx, cx
    shl  edx, 2
    or   eax, edx                       # ENT = cx, CTL 00
    mov  tr5, eax
    movzx bx, cl
    shl  bx, 2
    mov  eax, [pat + bx]
    mov  tr3, eax
    inc  cx
    cmp  cx, 4
    jb   2b
    mov  eax, [tag]
    or   eax, 0x400                     # valid
    mov  tr4, eax
    mov  eax, [setf]
    or   eax, 1                         # cache write, way 0
    mov  tr5, eax
    # ---- 3. cache read: TR4 and the read buffer (TR3, ENT = doubleword)
    mov  eax, [setf]
    or   eax, 2
    mov  tr5, eax
    mov  eax, tr4
    mov  [r_tr4b], eax
    xor  cx, cx
3:  mov  eax, [setf]
    movzx edx, cx
    shl  edx, 2
    or   eax, edx
    mov  tr5, eax
    mov  eax, tr3
    movzx bx, cl
    shl  bx, 2
    mov  [r_tr3 + bx], eax
    inc  cx
    cmp  cx, 4
    jb   3b
    # ---- 4. the buffer through a normal load (memory holds 'MEM0'..'MEM3')
    mov  eax, [buf]
    mov  [r_ld1], eax
    mov  eax, [buf + 12]
    mov  [r_ld1 + 4], eax
    # ---- 5. cache flush, load again
    mov  eax, 3
    mov  tr5, eax
    mov  eax, [buf]
    mov  [r_ld2], eax
    mov  eax, [buf + 12]
    mov  [r_ld2 + 4], eax
    mov  eax, [cr0s]
    mov  cr0, eax
    wbinvd
    sti
    # ---- report
    mov  si, offset s_pa
    call puts
    mov  eax, [pa]
    call puthex
    mov  si, offset s_tr4a
    call puts
    mov  eax, [r_tr4a]
    call puthex
    mov  si, offset s_tr4b
    call puts
    mov  eax, [r_tr4b]
    call puthex
    mov  si, offset s_tr3
    call puts
    xor  bx, bx
4:  mov  eax, [r_tr3 + bx]
    call puthex
    add  bx, 4
    cmp  bx, 16
    jb   4b
    mov  si, offset s_ld1
    call puts
    mov  eax, [r_ld1]
    call puthex
    mov  eax, [r_ld1 + 4]
    call puthex
    mov  si, offset s_ld2
    call puts
    mov  eax, [r_ld2]
    call puthex
    mov  eax, [r_ld2 + 4]
    call puthex
    mov  si, offset s_exp
    call puts
quit:
    cmp  word ptr [dos], 0
    je   5f
    mov  ax, 0x4C00
    int  0x21
5:  hlt

# print the zero-terminated string at DS:SI
puts:
    lodsb
    or   al, al
    jz   9f
    call putc
    jmp  puts
9:  ret
putc:
    cmp  word ptr [dos], 0
    je   1f
    push ax
    push dx
    mov  dl, al
    mov  ah, 2
    int  0x21
    pop  dx
    pop  ax
    ret
1:  out  0xE9, al
    ret
# EAX as 8 hex digits and a space
puthex:
    push cx
    mov  cx, 8
1:  rol  eax, 4
    push eax
    and  al, 0x0F
    add  al, '0'
    cmp  al, '9'
    jbe  2f
    add  al, 'A' - '0' - 10
2:  call putc
    pop  eax
    loop 1b
    mov  al, ' '
    call putc
    pop  cx
    ret

s_v86:  .asciz "TRTEST: the CPU is in V86 mode (EMM386?): run it in real mode.\r\n"
s_hdr:  .asciz "TRTEST: i486 cache test registers TR3-TR5\r\n"
s_pa:   .asciz "buffer at "
s_tr4a: .asciz "\r\nTR4 written 12345400, read: "
s_tr4b: .asciz "\r\nafter cache read, TR4: "
s_tr3:  .asciz "\r\nread buffer (TR3) : "
s_ld1:  .asciz "\r\nload with the line: "
s_ld2:  .asciz "\r\nload after flush  : "
s_exp:  .asciz "\r\n(written line 11111111 22222222 33333333 44444444; memory 304D454D ... 334D454D)\r\n"
.align 4
dos:    .word 0, 0
pa:     .long 0
setf:   .long 0
tag:    .long 0
cr0s:   .long 0
r_tr4a: .long 0
r_tr4b: .long 0
r_tr3:  .fill 4, 4, 0
r_ld1:  .long 0, 0
r_ld2:  .long 0, 0
pat:    .long 0x11111111, 0x22222222, 0x33333333, 0x44444444
.align 16
buf:    .ascii "MEM0MEM1MEM2MEM3"
