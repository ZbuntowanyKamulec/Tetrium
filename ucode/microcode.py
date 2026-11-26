# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""The Tetrium microcode: every instruction's micro-op sequence.

How to read / change it
-----------------------
An instruction is a list of micro-ops, U(...) (fields: ucode/uarch.py, class U), run in
order.  define() enters it in the dispatch table under its opcode:

    define(0x8B, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='REG')],    # mod != 3 (memory)
                 [U(e='PASSB', sb='RM', d1='REG')])                       # mod == 3 (register)
    define(0x9C, [U(sec='PUSH', e='PUSHF', sz='Z', wr='SEC')])           # no modrm: one list

    pg=1        an opcode of the 0F page
    regs=[...]  a group opcode (F6 F7 FE FF, 0F 00, 0F 01, 0F BA): the modrm.reg values
    mode='pm'   the protected-mode sequence (CR0.PE and not V86); without one an opcode runs
                its real-mode sequence in protected mode too

Each list is copied for every place it is entered (define() deep-copies; a function that
returns a fresh list works as well, as UD does), so one list can serve several opcodes.
Opcodes never defined raise #UD (filler entries at the end of this file).

Other entry points: INJ (sequences E micro-jumps to or decode injects: interrupt and
exception delivery, call gates, task switches, outer returns; their order is the inject id
used by tetrium_exec.sv) and IOV (I/O instructions at CPL > IOPL or in V86: the permission
bitmap check first).

Within a sequence: label= / goto= / lp= / label='self' (see U); the assembler (ucgen.py)
places the sequence and turns them into ROM addresses.  ucgen.py --list prints the result.

Dispatch index (the first uop's ROM address)
--------------------------------------------
    normal opcode : {page (0F), opcode[7:0], mod3}                     (0..1023)
    group opcode  : GROUP_BASE + group * 16 + reg * 2 + mod3            (1024..1135)
The decoder takes mod3 from the byte after the opcode, also for opcodes without modrm: both
entries then hold the same sequence (two copies).  Continuation uops, protected-mode, inject
and I/O sequences are placed from CONT_BASE on.
"""
import copy

from uarch import U

disp = {}          # real mode (and V86) dispatch: index -> sequence
disp_pm = {}       # protected-mode dispatch (missing entries: the real-mode sequence)
MR_SAME = set()    # (pm, index of the mod!=3 entry): one sequence for both mod forms (coverage)
GROUPS = {(0, 0xF6): 0, (0, 0xF7): 1, (0, 0xFE): 2, (0, 0xFF): 3, (1, 0x00): 4, (1, 0x01): 5, (1, 0xBA): 6}
GROUP_BASE = 1024
CONT_BASE = GROUP_BASE + 16 * 7


def didx(pg, op, mod3, reg=None):
    """dispatch index of an opcode (page pg, group register reg)"""
    if (pg, op) in GROUPS:
        return GROUP_BASE + GROUPS[(pg, op)] * 16 + ((reg & 7) << 1) + mod3
    return (pg << 9) | (op << 1) | mod3


def didx_name(idx):
    """opcode of a dispatch index: '0F B6 m', 'F7 /6 r' (m / r: the mod field selects memory /
    register; the two entries of an opcode without modrm hold the same sequence)"""
    mr = 'r' if idx & 1 else 'm'
    if idx >= GROUP_BASE:
        g = (idx - GROUP_BASE) >> 4
        pg, op = next(k for k, v in GROUPS.items() if v == g)
        return f"{'0F ' if pg else ''}{op:02X} /{(idx >> 1) & 7} {mr}"
    return f"{'0F ' if idx >> 9 else ''}{(idx >> 1) & 0xFF:02X} {mr}"


def fresh(seq):
    """a sequence's own copy of its uops (seq: a list of U, or a function returning one)"""
    return seq() if callable(seq) else copy.deepcopy(seq)


def define(op, seq_m, seq_r=None, regs=None, pg=0, mode='both'):
    """Enter a sequence in the dispatch table.  seq_m: the memory form (mod != 3), seq_r:
    the register form (mod == 3); without seq_r (no modrm, or the same uops for both) seq_m
    is used for both.  regs: the modrm.reg values of a group opcode (default all 8).
    mode: 'both' (the real-mode sequence, also used in protected mode), 'rm' (the same),
    'pm' (the protected-mode sequence)."""
    same = seq_r is None
    if seq_r is None:
        seq_r = seq_m
    rl = [None] if (pg, op) not in GROUPS else (regs if regs is not None else range(8))
    tab = disp_pm if mode == 'pm' else disp
    for reg in rl:
        if same:
            MR_SAME.add((mode == 'pm', didx(pg, op, 0, reg)))
        for mod3, seq in ((0, seq_m), (1, seq_r)):
            i = didx(pg, op, mod3, reg)
            if i in tab:
                raise ValueError(f'{"pm " if mode == "pm" else ""}{didx_name(i)}: defined twice')
            tab[i] = fresh(seq)


def UD():
    return [U(e='UD')]


# ================================================================= one-byte opcodes
ALU_OPS = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38]

# ALU r/m,r ; r,r/m ; acc,imm
for b in ALU_OPS:
    for w in (0, 1):
        # op r/m, r
        define(b | w,
               [U(a='EA', mrd=1, e='ALUOP', sa='MEM', sb='REG', wr='PRI')],
               [U(e='ALUOP', sa='RM', sb='REG', d1='RM')])
        # op r, r/m
        define(b | 2 | w,
               [U(a='EA', mrd=1, e='ALUOP', sa='REG', sb='MEM', d1='REG')],
               [U(e='ALUOP', sa='REG', sb='RM', d1='REG')])
        define(b | 4 | w, [U(e='ALUOP', sa='ACC', sb='IMM', d1='ACC')])

# segment push/pop (0F is the two-byte escape, there is no POP CS)
for s in range(4):
    define(0x06 | (s << 3), [U(sec='PUSH', e='PASSB', sb='SEG', sz='Z', wr='SEC')])
    if s != 1:
        define(0x07 | (s << 3), [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='SEG', sz='Z')])

define(0x27, [U(e='DAA', sa='ACC', sz='W16')])
define(0x2F, [U(e='DAS', sa='ACC', sz='W16')])
define(0x37, [U(e='AAA', sa='ACC', sz='W16')])
define(0x3F, [U(e='AAS', sa='ACC', sz='W16')])

for r in range(8):
    define(0x40 + r, [U(e='INC', sa='OPR', d1='OPR', sz='Z')])
    define(0x48 + r, [U(e='DEC', sa='OPR', d1='OPR', sz='Z')])
    define(0x50 + r, [U(sec='PUSH', e='PASSB', sb='OPR', sz='Z', wr='SEC')])   # PUSH SP: the old value
    define(0x58 + r, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='OPR', sz='Z')])

# PUSHA: AX CX DX BX (original SP) BP SI DI;  POPA: the reverse, the SP slot read but not
# written; a fault keeps the registers popped before it (386EX SingleStepTests 61 / 6661)
define(0x60, [U(sec='PUSH', e='XCHG', sa='FIX', rfix=4, sb='ACC', d2='T0', sz='Z', wr='SEC'),
              U(sec='PUSH', e='PASSB', sb='FIX', rfix=1, sz='Z', wr='SEC'),
              U(sec='PUSH', e='PASSB', sb='FIX', rfix=2, sz='Z', wr='SEC'),
              U(sec='PUSH', e='PASSB', sb='FIX', rfix=3, sz='Z', wr='SEC'),
              U(sec='PUSH', e='PASSB', sb='T0', sz='Z', wr='SEC'),
              U(sec='PUSH', e='PASSB', sb='FIX', rfix=5, sz='Z', wr='SEC'),
              U(sec='PUSH', e='PASSB', sb='FIX', rfix=6, sz='Z', wr='SEC'),
              U(sec='PUSH', e='PASSB', sb='FIX', rfix=7, sz='Z', wr='SEC')])
define(0x61, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=7, sz='Z'),
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=6, sz='Z'),
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=5, sz='Z'),
              U(a='POP', mrd=1, e='NOP', sz='Z'),   # (E)SP slot: read, value dropped (386EX: limit / page checked)
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=3, sz='Z'),
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=2, sz='Z'),
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=1, sz='Z'),
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=0, sz='Z')])
# BOUND r, m: #BR unless m[0] <= r <= m[1] (signed)
# (both bounds are limit-checked before either is read: the upper one by a probe first;
#  EA2 is not valid in an instruction's first uop, hence the NOP)
define(0x62, [U(e='NOP'),
              U(a='EA2', mrd=1, e='RPROBE', sz='Z'),
              U(a='EA', mrd=1, e='BOUND', sa='REG', sb='MEM', sz='Z'),
              U(a='EA2', mrd=1, e='BOUND', sa='MEM', sb='REG', sz='Z')], UD)
for op in (0x69, 0x6B):                # IMUL r, r/m, imm
    define(op, [U(a='EA', mrd=1, e='IMUL2', sa='MEM', sb='IMM', d1='REG', sz='Z')],
           [U(e='IMUL2', sa='RM', sb='IMM', d1='REG', sz='Z')])
for w in (0, 1):                       # INS / OUTS
    define(0x6C | w, [U(sec='STDI', repchk=1, e='IN', sa='DX', wr='SEC', label='self', endnr=1)])
    define(0x6E | w, [U(a='SI', mrd=1, repchk=1, e='OUT', sa='DX', sb='MEM', label='self', endnr=1)])
define(0x68, [U(sec='PUSH', e='PASSB', sb='IMM', sz='Z', wr='SEC')])
define(0x6A, [U(sec='PUSH', e='PASSB', sb='IMM', sz='Z', wr='SEC')])

for c in range(16):
    define(0x70 + c, [U(abr='BRE', e='JCC')])
    define(0x80 + c, [U(abr='BRE', e='JCC')], pg=1)
    define(0x90 + c, [U(a='EA', e='SETCC', sz='B', wr='PRI')],
           [U(e='SETCC', d1='RM', sz='B')], pg=1)

for op in (0x80, 0x81, 0x82, 0x83):
    define(op, [U(a='EA', mrd=1, e='ALUREG', sa='MEM', sb='IMM', wr='PRI')],
           [U(e='ALUREG', sa='RM', sb='IMM', d1='RM')])
for w in (0, 1):
    define(0x84 | w, [U(a='EA', mrd=1, e='TEST', sa='MEM', sb='REG')],
           [U(e='TEST', sa='RM', sb='REG')])
    define(0x86 | w, [U(a='EA', mrd=1, e='XCHG', sa='MEM', sb='REG', d2='REG', wr='PRI')],
           [U(e='XCHG', sa='RM', sb='REG', d1='RM', d2='REG')])
    define(0x88 | w, [U(a='EA', e='PASSB', sb='REG', wr='PRI')],
           [U(e='PASSB', sb='REG', d1='RM')])
    define(0x8A | w, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='REG')],
           [U(e='PASSB', sb='RM', d1='REG')])
# MOV r/m, Sreg: memory form stores 16 bits, register form writes the operand size
define(0x8C, [U(a='EA', e='PASSB', sb='SEG', sz='W16', wr='PRI')],
       [U(e='PASSB', sb='SEG', d1='RM', sz='Z')])
define(0x8D, [U(a='EAC', e='LEA', d1='REG', sz='Z')], UD)
define(0x8E, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='SEG', sz='W16')],
       [U(e='PASSB', sb='RM', d1='SEG', sz='W16')])
define(0x8F, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
              U(a='EA', e='PASSB', sb='T0', sz='Z', wr='PRI')],
       [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='RM', sz='Z')])
define(0x90, [U(e='NOP')])
for r in range(1, 8):
    define(0x90 + r, [U(e='XCHG', sa='ACC', sb='OPR', d1='ACC', d2='OPR', sz='Z')])
define(0x98, [U(e='CBW', sa='ACC', sz='Z')])
define(0x99, [U(e='CWD', sa='ACC', sz='Z')])
define(0x9A, [U(sec='PUSH', e='PASSB', sb='CS', sz='Z', wr='SEC'),
              U(sec='PUSH', abr='BRI', e='JFAR', sa='IMM', sb='DISP', sz='Z', wr='SEC')])
define(0x9B, [U(e='ESC')])                     # WAIT
define(0x9C, [U(sec='PUSH', e='PUSHF', sz='Z', wr='SEC', chk='V86IOPL')])
define(0x9D, [U(a='POP', mrd=1, e='POPF', sb='MEM', sz='Z', chk='V86IOPL')])
define(0x9E, [U(e='SAHF', sa='ACC', sz='W16')])
define(0x9F, [U(e='LAHF')])
for w in (0, 1):
    define(0xA0 | w, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='ACC')])
    define(0xA2 | w, [U(a='EA', e='PASSB', sb='ACC', wr='PRI')])
    define(0xA4 | w, [U(a='SI', mrd=1, sec='STDI', repchk=1, e='PASSB', sb='MEM', wr='SEC',
                        label='self', endnr=1)])
    # CMPS reads ES:EDI first, then DS:ESI (386 microcode order, as 86Box: decides which #PF / walk comes first)
    define(0xA6 | w, [U(a='DI', mrd=1, repchk=1, e='PASSB', sb='MEM', d1='T0', label='top'),
                      U(a='SI', mrd=1, e='CMP', sa='MEM', sb='T0', repz=1, goto='top', endnr=1)])
    define(0xA8 | w, [U(e='TEST', sa='ACC', sb='IMM')])
    define(0xAA | w, [U(sec='STDI', repchk=1, e='PASSB', sb='ACC', wr='SEC', label='self', endnr=1)])
    define(0xAC | w, [U(a='SI', mrd=1, repchk=1, e='PASSB', sb='MEM', d1='ACC', label='self', endnr=1)])
    define(0xAE | w, [U(a='DI', mrd=1, repchk=1, e='CMP', sa='ACC', sb='MEM', repz=1,
                        label='self', endnr=1)])
for r in range(8):
    define(0xB0 + r, [U(e='PASSB', sb='IMM', d1='OPR', sz='W3')])
    define(0xB8 + r, [U(e='PASSB', sb='IMM', d1='OPR', sz='W3')])
for op in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
    define(op, [U(a='EA', mrd=1, e='SHIFT', sa='MEM', wr='PRI')],
           [U(e='SHIFT', sa='RM', d1='RM')])
define(0xC2, [U(a='POPN', mrd=1, abr='BRI', e='JNEAR', sa='MEM', sz='Z')])
define(0xC3, [U(a='POP', mrd=1, abr='BRI', e='JNEAR', sa='MEM', sz='Z')])
for op in (0xC4, 0xC5):
    define(op, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
                U(a='EA2', mrd=1, m16=1, e='PASSA', sa='MEM', sb='T0', d1='SEG', d2='REG', sz='Z')],
           UD)
define(0xC6, [U(a='EA', e='PASSB', sb='IMM', wr='PRI')], [U(e='PASSB', sb='IMM', d1='RM')])
define(0xC7, [U(a='EA', e='PASSB', sb='IMM', wr='PRI')], [U(e='PASSB', sb='IMM', d1='RM')])
# LEAVE: SP / ESP <- BP / EBP (stack size), BP / EBP <- pop (operand size)
# ENTER size, level: push BP; frame = SP; (level - 1) x { BP' -= size; push [SS:BP'] };
# push frame (if level > 0); BP = frame; SP -= size.  T0 walks down the old frame, T1 = frame.
define(0xC8, [U(sec='PUSH', e='PASSB', sb='BP', sz='Z', wr='SEC'),
              U(e='PASSB', sb='FIX', rfix=4, d1='T1', sz='D32', lp='G'),   # frame: SP / ESP by operand size
              U(e='PASSB', sb='BP', d1='T0', sz='SS', lp='X'),
              U(e='SUBNF', sa='T0', sb='OPSZ', d1='T0', sz='Z', label='top'),
              U(a='TAS', mrd=1, sec='PUSH', e='PASSB', sb='MEM', sz='Z', wr='SEC', goto='top', lp='X'),
              U(e='NOP', label='X'),
              U(sec='PUSH', e='PASSB', sb='T1', sz='Z', wr='SEC', goto='G'),
              # the final SS:(E)SP must take a write (#SS / #PF, nothing written: SDM,
              # 80386 microcode check-write) before (E)BP / (E)SP change
              U(e='SUBNF', sa='FIX', rfix=4, sb='IMM', d1='T0', sz='SS', label='G'),
              U(a='TAS', e='PROBE', sz='Z', wr='PRI'),
              U(e='PASSB', sb='T1', d1='FIX', rfix=5, sz='Z'),
              U(e='PASSB', sb='T0', d1='FIX', rfix=4, sz='SS')])
define(0xC9, [U(e='PASSB', sb='BP', d1='FIX', rfix=4, sz='SS'),
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='FIX', rfix=5, sz='Z')])
define(0xCA, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
              U(a='POPN', mrd=1, abr='BRI', e='JFAR', sa='MEM', sb='T0', sz='Z')])
define(0xCB, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
              U(a='POP', mrd=1, abr='BRI', e='JFAR', sa='MEM', sb='T0', sz='Z')])
define(0xCC, [U(e='INT', sz='W16')])                      # INT3, INTO: not IOPL-sensitive in V86
define(0xCD, [U(e='INT', sz='W16', chk='V86IOPL')])
define(0xCE, [U(e='INTO', sz='W16')])
define(0xCF, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z', chk='V86IOPL'),
              U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T1', sz='Z'),
              U(a='POP', mrd=1, e='IRET', sb='MEM', sz='Z')])
define(0xD4, [U(e='AAM', sa='ACC', sz='W16')])
define(0xD5, [U(e='AAD', sa='ACC', sz='W16')])
define(0xD6, [U(e='SALC', sz='B')])
define(0xD7, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='ACC', sz='B')])
# ESC without a coprocessor: the modrm is decoded, nothing else happens (#NM if CR0.EM / TS)
for op in range(0xD8, 0xE0):
    define(op, [U(e='ESC')])
define(0xE0, [U(abr='LOOPNZ', e='LOOPCC')])
define(0xE1, [U(abr='LOOPZ', e='LOOPCC')])
define(0xE2, [U(abr='LOOP', e='NOP')])
define(0xE3, [U(abr='JCXZ', e='NOP')])
for w in (0, 1):
    define(0xE4 | w, [U(e='IN', sa='IMM', d1='ACC')])
    define(0xE6 | w, [U(e='OUT', sa='IMM', sb='ACC')])
    define(0xEC | w, [U(e='IN', sa='DX', d1='ACC')])
    define(0xEE | w, [U(e='OUT', sa='DX', sb='ACC')])
define(0xE8, [U(sec='PUSH', abr='JMPD', e='PASSB', sb='IPN', sz='Z', wr='SEC')])
define(0xE9, [U(abr='JMPD', e='NOP')])
define(0xEA, [U(abr='BRI', e='JFAR', sa='IMM', sb='DISP', sz='Z')])
define(0xEB, [U(abr='JMPD', e='NOP')])
define(0xF4, [U(e='HLT', chk='CPL0')])
for op in (0xF5, 0xF8, 0xF9, 0xFC, 0xFD):
    define(op, [U(e='FLAGOP')])
for op in (0xFA, 0xFB):                # CLI / STI
    define(op, [U(e='FLAGOP', chk='IOPL')])
# group 3
for op in (0xF6, 0xF7):
    define(op, [U(a='EA', mrd=1, e='TEST', sa='MEM', sb='IMM')],
           [U(e='TEST', sa='RM', sb='IMM')], regs=[0, 1])
    define(op, [U(a='EA', mrd=1, e='NOT', sa='MEM', wr='PRI')],
           [U(e='NOT', sa='RM', d1='RM')], regs=[2])
    define(op, [U(a='EA', mrd=1, e='NEG', sa='MEM', wr='PRI')],
           [U(e='NEG', sa='RM', d1='RM')], regs=[3])
    define(op, [U(a='EA', mrd=1, e='MUL', sa='ACC', sb='MEM')],
           [U(e='MUL', sa='ACC', sb='RM')], regs=[4, 5])
    define(op, [U(a='EA', mrd=1, e='DIV', sb='MEM')],
           [U(e='DIV', sb='RM')], regs=[6, 7])
# group 4/5
for op in (0xFE, 0xFF):
    define(op, [U(a='EA', mrd=1, e='INC', sa='MEM', wr='PRI')],
           [U(e='INC', sa='RM', d1='RM')], regs=[0])
    define(op, [U(a='EA', mrd=1, e='DEC', sa='MEM', wr='PRI')],
           [U(e='DEC', sa='RM', d1='RM')], regs=[1])
define(0xFF, [U(a='EA', mrd=1, sec='PUSH', abr='BRI', e='JNEAR', sa='MEM', sz='Z', wr='SEC')],
       [U(sec='PUSH', abr='BRI', e='JNEAR', sa='RM', sz='Z', wr='SEC')], regs=[2])
define(0xFF, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
              U(a='EA2', mrd=1, m16=1, sec='PUSH', e='XCHG', sa='MEM', sb='CS', d2='T1', sz='Z', wr='SEC'),
              U(sec='PUSH', abr='BRI', e='JFAR', sa='T1', sb='T0', sz='Z', wr='SEC')], UD, regs=[3])
define(0xFF, [U(a='EA', mrd=1, abr='BRI', e='JNEAR', sa='MEM', sz='Z')],
       [U(abr='BRI', e='JNEAR', sa='RM', sz='Z')], regs=[4])
define(0xFF, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
              U(a='EA2', mrd=1, m16=1, abr='BRI', e='JFAR', sa='MEM', sb='T0', sz='Z')], UD, regs=[5])
define(0xFF, [U(a='EA', mrd=1, sec='PUSH', e='PASSB', sb='MEM', sz='Z', wr='SEC')],
       [U(sec='PUSH', e='PASSB', sb='RM', sz='Z', wr='SEC')], regs=[6])

# ================================================================= 0F page
# system registers (real mode: CPL 0).  SGDT / SIDT / LGDT / LIDT: limit at EA, base at
# EA + 2 (T0 = EA); LGDT / LIDT with a 16-bit operand size load a 24-bit base.
def sdt_store(lim, base):
    # (EA2 of the 0F 01 group: EA + 2 at either operand size; all 6 bytes are limit-checked
    #  before the first store: the base part by a probe, see BOUND)
    return [U(e='NOP'),
            U(a='EA2', mrd=1, e='RPROBE', sz='D32'),
            U(a='EA', e='SRD', rfix=lim, sz='W16', wr='PRI'),
            U(a='EA2', e='SRD', rfix=base, sz='D32', wr='PRI')]
def sdt_load(r):
    return [U(a='EAC', e='LEA', d1='T0', sz='Z', chk='CPL0'),
            U(a='EA2', mrd=1, e='RPROBE', sz='D32'),     # (the base part: limit first)
            U(a='TA', mrd=1, e='PASSB', sb='MEM', d1='T1', sz='W16'),
            U(e='ADDNF', sa='T0', sb='OPSZ', d1='T0', sz='W16'),
            U(a='TA', mrd=1, e='SWR', rfix=r, sb='MEM', sz='D32')]
define(0x01, sdt_store(1, 2), UD, regs=[0], pg=1)                  # SGDT
define(0x01, sdt_store(3, 4), UD, regs=[1], pg=1)                  # SIDT
define(0x01, sdt_load(2), UD, regs=[2], pg=1)                      # LGDT
define(0x01, sdt_load(3), UD, regs=[3], pg=1)                      # LIDT
define(0x01, [U(a='EA', e='SRD', rfix=0, sz='W16', wr='PRI')],
       [U(e='SRD', rfix=0, d1='RM', sz='Z')], regs=[4], pg=1)          # SMSW (r32: all of CR0, 80386 microcode)
define(0x01, [U(a='EA', mrd=1, e='SWR', rfix=0, sb='MEM', sz='W16', chk='CPL0')],
       [U(e='SWR', rfix=0, sb='RM', sz='W16', chk='CPL0')], regs=[6], pg=1)        # LMSW
define(0x01, [U(a='EA', e='INVLPG', chk='CPL0')], UD, regs=[7], pg=1)              # INVLPG
define(0x06, [U(e='SWR', rfix=1, chk='CPL0')], pg=1)                               # CLTS
for op in (0x08, 0x09):                # INVD / WBINVD (write-through caches: the same)
    define(op, [U(e='CINV', chk='CPL0')], pg=1)
# MOV r32, CRn / MOV CRn, r32 (the modrm always names a register)
define(0x20, [U(e='SRD', rfix=7, d1='RM', sz='D32', chk='CPL0')], pg=1)
define(0x22, [U(e='SWR', rfix=7, sb='RM', sz='D32', chk='CPL0')], pg=1)
# MOV r32, DRn / MOV DRn, r32 (TRD / TWR uops, op[2] = 0: debug registers; DR7.GD: #DB)
define(0x21, [U(e='TRD', d1='RM', sz='D32', chk='CPL0')], pg=1)
define(0x23, [U(e='TWR', sb='RM', sz='D32', chk='CPL0')], pg=1)
# MOV r32, TRn / MOV TRn, r32
define(0x24, [U(e='TRD', d1='RM', sz='D32', chk='CPL0')], pg=1)
define(0x26, [U(e='TWR', sb='RM', sz='D32', chk='CPL0')], pg=1)
# CPUID: EBX, ECX, EDX from the leaf in EAX, then EAX
define(0xA2, [U(e='CPUID', sa='ACC', d1='FIX', rfix=3, sz='D32'),
              U(e='CPUID', sa='ACC', d1='FIX', rfix=1, sz='D32'),
              U(e='CPUID', sa='ACC', d1='FIX', rfix=2, sz='D32'),
              U(e='CPUID', sa='ACC', d1='FIX', rfix=0, sz='D32')], pg=1)
define(0xA0, [U(sec='PUSH', e='PASSB', sb='SEG', sz='Z', wr='SEC')], pg=1)
define(0xA8, [U(sec='PUSH', e='PASSB', sb='SEG', sz='Z', wr='SEC')], pg=1)
define(0xA1, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='SEG', sz='Z')], pg=1)
define(0xA9, [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='SEG', sz='Z')], pg=1)
for op in (0xB2, 0xB4, 0xB5):          # LSS / LFS / LGS
    define(op, [U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
                U(a='EA2', mrd=1, m16=1, e='PASSA', sa='MEM', sb='T0', d1='SEG', d2='REG', sz='Z')],
           UD, pg=1)
for op in (0xB6, 0xB7, 0xBE, 0xBF):    # MOVZX / MOVSX (source size from op[0], see exec)
    define(op, [U(a='EA', mrd=1, e='MOVX', sb='MEM', d1='REG', sz='Z')],
           [U(e='MOVX', sb='RM', d1='REG', sz='Z')], pg=1)
for r in range(8):
    define(0xC8 + r, [U(e='BSWAP', sa='OPR', d1='OPR', sz='D32')], pg=1)
define(0xAF, [U(a='EA', mrd=1, e='IMUL2', sa='REG', sb='MEM', d1='REG', sz='Z')],
       [U(e='IMUL2', sa='REG', sb='RM', d1='REG', sz='Z')], pg=1)
# bit tests: the register bit offset of a memory operand selects the word (T0 = its address)
define(0xA3, [U(a='EAC', e='BTADR', sb='REG', d1='T0', sz='Z'),
              U(a='TA', mrd=1, e='BT', sa='MEM', sb='REG', sz='Z')],
       [U(e='BT', sa='RM', sb='REG', sz='Z')], pg=1)
for op in (0xAB, 0xB3, 0xBB):
    define(op, [U(a='EAC', e='BTADR', sb='REG', d1='T0', sz='Z'),
                U(a='TA', mrd=1, e='BT', sa='MEM', sb='REG', sz='Z', wr='PRI')],
           [U(e='BT', sa='RM', sb='REG', d1='RM', sz='Z')], pg=1)
define(0xBA, [U(a='EA', mrd=1, e='BT', sa='MEM', sb='IMM', sz='Z')],
       [U(e='BT', sa='RM', sb='IMM', sz='Z')], regs=[4], pg=1)
define(0xBA, [U(a='EA', mrd=1, e='BT', sa='MEM', sb='IMM', sz='Z', wr='PRI')],
       [U(e='BT', sa='RM', sb='IMM', d1='RM', sz='Z')], regs=[5, 6, 7], pg=1)
for op in (0xBC, 0xBD):                # BSF / BSR
    define(op, [U(a='EA', mrd=1, e='BSF', sa='REG', sb='MEM', d1='REG', sz='Z')],
           [U(e='BSF', sa='REG', sb='RM', d1='REG', sz='Z')], pg=1)
for op in (0xA4, 0xA5, 0xAC, 0xAD):    # SHLD / SHRD
    define(op, [U(a='EA', mrd=1, e='SHXD', sa='MEM', sb='REG', sz='Z', wr='PRI')],
           [U(e='SHXD', sa='RM', sb='REG', d1='RM', sz='Z')], pg=1)
for op in (0xC0, 0xC1):                # XADD
    define(op, [U(a='EA', mrd=1, e='XADD', sa='MEM', sb='REG', d2='REG', wr='PRI')],
           [U(e='XADD', sa='RM', sb='REG', d1='RM', d2='REG')], pg=1)
for op in (0xB0, 0xB1):                # CMPXCHG: compare, then two conditional moves
    define(op, [U(a='EA', mrd=1, e='CMP', sa='ACC', sb='MEM', d2='T0'),
                U(a='EA', e='CSEL', sa='T0', sb='REG', wr='PRI'),
                U(e='CSEL', sa='T0', sb='ACC', d1='ACC')],
           [U(e='CMP', sa='ACC', sb='RM', d2='T0'),
            U(e='CSEL', sa='T0', sb='REG', d1='RM'),
            U(e='CSEL', sa='T0', sb='ACC', d1='ACC')], pg=1)

# ================================================================= protected mode
# Segment register loads: the selector goes to T0 (from memory / the stack), then the
# descriptor's low dword (DLO: table limit / null checks; R2 = the selector) and high
# dword (DHI: type / privilege / present checks, loads the segment register, sets the
# accessed bit with a byte store).  A register selector is read by the address mode
# itself (DSCR), so MOV Sreg, r is two uops.
def dsc_load(src_first, a, rd=None):
    """src_first: uops that leave the selector in T0 (or [] with a = 'DSCR')"""
    lo = U(a=a, aoff=0, mrd=1, e='DLO', ck='SEG', sa=('RM' if a == 'DSCR' else 'T0'), sb='MEM',
           d1='T1', d2=('NONE' if a == 'DSCT' else 'T0'), sz='D32')
    hi = U(a=a, aoff=4, mrd=1, sec='DSCA', e='DHI', ck='SEG', sa='T0', sb='MEM', d1='SEG',
           sz='B', wr='SEC')
    return src_first + [lo, hi] + (rd or [])
define(0x8E, dsc_load([U(a='EA', mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16')], 'DSCT'),
       dsc_load([], 'DSCR'), mode='pm')
for sg in (0, 2, 3):
    define(0x07 | (sg << 3), dsc_load([U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z')], 'DSCT'),
           mode='pm')
for op in (0xA1, 0xA9):
    define(op, dsc_load([U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z')], 'DSCT'), pg=1, mode='pm')
# LDS / LES / LSS / LFS / LGS: offset to T2, selector to T0; the register is written last
def lxs():
    return dsc_load([U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='T2', sz='Z'),
                     U(a='EA2', mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16')], 'DSCT',
                    [U(e='PASSB', sb='T2', d1='REG', sz='Z')])
for op in (0xC4, 0xC5):
    define(op, lxs, UD, mode='pm')
for op in (0xB2, 0xB4, 0xB5):
    define(op, lxs, UD, pg=1, mode='pm')
# far JMP: EIP to T2, selector to T0, descriptor checks, LDCS loads CS and jumps
def far_cs(first, a, ck):
    lo = U(a=a, aoff=0, mrd=1, e='DLO', ck=ck, sa=('IMM' if a == 'DSCI' else 'T0'), sb='MEM',
           d1='T1', d2=('NONE' if a == 'DSCT' else 'T0'), sz='D32')
    hi = U(a=a, aoff=4, mrd=1, sec='DSCA', e='DHI', ck=ck, sa='T0', sb='MEM', d2='T3', sz='B', wr='SEC')
    return first + [lo, hi]
# (abr BRI on the LDCS of far JMP / CALL / RETF: one that keeps CS is verified in E and
# needs no redirect when predicted, see tetrium_exec.sv)
define(0xEA, far_cs([U(e='PASSB', sb='DISP', d1='T2', sz='Z')], 'DSCI', 'CSJ') +
       [U(abr='BRI', e='LDCS', ck='CSJ', sz='Z')], mode='pm')
define(0xFF, far_cs([U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='T2', sz='Z'),
                     U(a='EA2', mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16')], 'DSCT', 'CSJ') +
       [U(abr='BRI', e='LDCS', ck='CSJ', sz='Z')], UD, regs=[5], mode='pm')
# group 0F 00 (protected mode only; #UD in real mode and V86): SLDT STR LLDT LTR
define(0x00, [U(a='EA', e='SRD', rfix=5, sz='W16', wr='PRI')],
       [U(e='SRD', rfix=5, d1='RM', sz='W16')], regs=[0], pg=1, mode='pm')
define(0x00, [U(a='EA', e='SRD', rfix=6, sz='W16', wr='PRI')],
       [U(e='SRD', rfix=6, d1='RM', sz='W16')], regs=[1], pg=1, mode='pm')
for rg, ck in ((2, 'LDT'), (3, 'TSS')):
    def sysdsc(a, ck=ck, first=None):
        lo = U(a=a, aoff=0, mrd=1, e='DLO', ck=ck, sa=('RM' if a == 'DSCR' else 'T0'), sb='MEM',
               d1='T1', d2=('NONE' if a == 'DSCT' else 'T0'), sz='D32', chk='CPL0' if not first else 'NONE')
        hi = U(a=a, aoff=4, mrd=1, sec='DSCA', e='DHI', ck=ck, sa='T0', sb='MEM', sz='B',
               wr='SEC' if ck == 'TSS' else 'NONE')
        return (first or []) + [lo, hi]
    define(0x00, sysdsc('DSCT', first=[U(a='EA', mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0',
                                         sz='W16', chk='CPL0')]),
           sysdsc('DSCR'), regs=[rg], pg=1, mode='pm')

# far CALL: checks first, then the pushes; the last push loads CS
def far_call(first, a):
    return far_cs(first, a, 'CSC') + [U(sec='PUSH', e='PASSB', sb='CS', sz='Z', wr='SEC'),
                                      U(sec='PUSH', abr='BRI', e='LDCS', ck='CSC', sz='Z', wr='SEC')]
define(0x9A, far_call([U(e='PASSB', sb='DISP', d1='T2', sz='Z')], 'DSCI'), mode='pm')
define(0xFF, far_call([U(a='EA', mrd=1, e='PASSB', sb='MEM', d1='T2', sz='Z'),
                       U(a='EA2', mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16')], 'DSCT'),
       UD, regs=[3], mode='pm')
# far RET (n): EIP to T2, CS to T0
for op in (0xCA, 0xCB):
    define(op, far_cs([U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T2', sz='Z'),
                       U(a='POPN' if op == 0xCA else 'POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z')],
                      'DSCT', 'CSR') + [U(abr='BRI', e='LDCS', ck='CSR', sz='Z')], mode='pm')
# IRET: EIP to T2, CS to T0, EFLAGS to T4; LDCS loads CS and the flags (from B = T4)
define(0xCF, far_cs([U(e='IRNT', sz='Z'),
                     U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T2', sz='Z'),
                     U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
                     U(a='POP', mrd=1, e='IRVM', sb='MEM', d1='T4', sz='Z')], 'DSCT', 'CSI') +
       [U(e='LDCS', ck='CSI', sb='T4', sz='Z')], mode='pm')

# LAR / LSL (0F 02 / 03), VERR / VERW (0F 00 /4 /5): the selector to T0, the descriptor
# (LSL: low dword to T1) is read without faulting, ZF tells; the NOP keeps the next instruction's
# bypass off the result of an invalid one (not written)
def lar(ck, rd):
    def mk(m):
        first = [U(a='EA', mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16')] if m else []
        a = 'DSCT' if m else 'DSCR'
        sel = 'T0' if m else 'RM'
        lo = [U(a=a, aoff=0, mrd=1, e='DLO', ck='ACC', sa=sel, sb='MEM', d1='T1', sz='D32')] if ck == 'LSL' else []
        return first + lo + [U(a=a, aoff=4, mrd=1, e='LARV', ck=ck, sa=sel, sb='MEM', d1=('REG' if rd else 'NONE'),
                               sz=('Z' if rd else 'W16'))] + ([U(e='NOP')] if rd else [])
    return mk(True), mk(False)
for op, ck in ((0x02, 'LAR'), (0x03, 'LSL')):
    m_, r_ = lar(ck, True)
    define(op, m_, r_, pg=1, mode='pm')
for rg, ck in ((4, 'VERR'), (5, 'VERW')):
    m_, r_ = lar(ck, False)
    define(0x00, m_, r_, regs=[rg], pg=1, mode='pm')
# ARPL r/m16, r16 (protected mode only)
define(0x63, [U(a='EA', mrd=1, e='ARPL', sa='MEM', sb='REG', sz='W16', wr='PRI')],
       [U(e='ARPL', sa='RM', sb='REG', d1='RM', sz='W16')], mode='pm')

# I/O instructions at CPL > IOPL (or V86): the I/O permission bitmap is checked first
# (decode dispatches here instead; port in DX or the immediate)
def iochk(port, body):
    return [U(a='TSSA', aoff=0x66, mrd=1, m16=1, e='IOMAP', sa=port, sb='MEM', d1='T0', sz='W16'),
            U(a='TSS', aoff=0, mrd=1, e='IOBIT', sa=port, sb='MEM', sz='W16')] + body
IOV = {}
for w in (0, 1):
    IOV[0xE4 | w] = iochk('IMM', [U(e='IN', sa='IMM', d1='ACC')])
    IOV[0xE6 | w] = iochk('IMM', [U(e='OUT', sa='IMM', sb='ACC')])
    IOV[0xEC | w] = iochk('DX', [U(e='IN', sa='DX', d1='ACC')])
    IOV[0xEE | w] = iochk('DX', [U(e='OUT', sa='DX', sb='ACC')])
    IOV[0x6C | w] = iochk('DX', [U(sec='STDI', repchk=1, e='IN', sa='DX', wr='SEC', label='self', endnr=1)])
    IOV[0x6E | w] = iochk('DX', [U(a='SI', mrd=1, repchk=1, e='OUT', sa='DX', sb='MEM', label='self', endnr=1)])

# Prefix / escape bytes: never dispatched (handled in decode) -> NOP entries (placeholders:
# not counted by the coverage report)
def PFX():
    sq = [U(e='NOP')]
    sq[0].fill = True
    return sq


for op in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x0F):
    define(op, PFX)

# ================================================================= inject sequences
# Interrupt sequence (injected by decode; ctx.imm = vector, ctx.ip_next = return IP)
INT_SEQ = [U(a='VEC', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='W16'),
           U(a='VEC2', mrd=1, e='PASSB', sb='MEM', d1='T1', sz='W16'),
           U(sec='PUSH', e='INTFL', sz='W16', wr='SEC'),
           U(sec='PUSH', e='PASSB', sb='CS', sz='W16', wr='SEC'),
           U(sec='PUSH', e='JFAR', sa='T1', sb='T0', sz='W16', wr='SEC')]
# Protected-mode interrupt / exception entry (injected, vector in imm): the gate (DLO:
# IDT limit, DHI: type / DPL / present) leaves the new EIP in T2 and the selector in T0,
# then E micro-jumps to the frame sequence for the gate size (with or without an error
# code; operand size = gate size).
INT_PM = [U(a='IDT', aoff=0, mrd=1, e='DLO', ck='INTG', sb='MEM', d1='T1', sz='D32'),
          U(a='IDT', aoff=4, mrd=1, e='DHI', ck='INTG', sb='MEM', d1='T2', d2='T0', sz='D32')]
# (after a stack switch the CS accessed bit is already set: stack_in's ACC uop; a second
# one would store again, its high dword in T3 being the copy read before)
def int_tail(ck, sv=0, acc=True):
    return ([U(sec='PUSH', e='EFL', sz='Z', wr='SEC', sv=sv),
             U(sec='PUSH', e='PASSB', sb='CS', sz='SEL', wr='SEC', sv=sv),
             U(sec='PUSH', e='PASSB', sb='IPN', sz='Z', wr='SEC', sv=sv),
             U(sec='PUSH', e='PASSB', sb='ERRC', sz='Z', wr='SEC', ifec=1, sv=sv)] +
            ([U(a='DSCT', aoff=4, sec='DSCA', e='DHI', ck='ACC', sa='T0', sb='T3', sz='B', wr='SEC')] if acc else []) +
            [U(e='LDCS', ck=ck, sz='Z')])
INT_FRAME = ([U(a='DSCT', aoff=0, mrd=1, e='DLO', ck='INTCS', sa='T0', sb='MEM', d1='T1', sz='D32'),
              U(a='DSCT', aoff=4, mrd=1, e='DHI', ck='INTCS', sa='T0', sb='MEM', d2='T3', sz='D32')] +
             int_tail('INTCS'))
# Stack switch to the inner level (CALL through a gate, interrupt): CS selector, low and
# high dword in T0 / T1 / T3, EIP in T2.  Old SS -> T4, old (E)SP -> T9, CS selector -> T6,
# new (E)SP -> T7; SS is loaded (low dword in T5), then (E)SP.
def stack_in(params, v86=False, gate=True):
    sq = [U(e='PASSB', sb='SSR', d1='T4', sz='W16'),
          U(e='OLDSP', d1='T9', sz='D32') if gate else U(e='PASSB', sb='FIX', rfix=4, d1='T9', sz='D32'),
          U(e='PASSB', sb='T0', d1='T6', sz='D32')]
    if params:
        # linear address after the parameters on the old stack: SS base + (E)SP + their bytes
        sq += [U(e='SSB', d1='T0', sz='D32'),
               U(e='ADDNF', sa='T0', sb='T9', d1='T0', sz='D32'),
               U(e='ADDNF', sa='T0', sb='GPSZ', d1='T8', sz='D32')]
    sq += [U(e='TSSOFF', sa='T3', d1='T0', sz='D32'),
           U(a='TSS', aoff=0, mrd=1, e='PASSB', sb='MEM', d1='T7', sz='TSZ'),
           U(a='TSS', aoff=4, mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16'),
           U(a='DSCT', aoff=0, mrd=1, e='DLO', ck='NSS', sa='T0', sb='MEM', d1='T5', sz='D32'),
           U(a='DSCT', aoff=4, mrd=1, sec='DSCA', e='DHI', ck='NSS', sa='T0', sb='MEM', d1='SSR',
             sz='B', wr='SEC'),
           U(e='LDSP', sb='T7', d1='FIX', rfix=4, sz='D32'),
           U(e='PASSB', sb='T6', d1='T0', sz='D32'),
           U(a='DSCT', aoff=4, sec='DSCA', e='DHI', ck='ACC', sa='T0', sb='T3', sz='B', wr='SEC')]
    # (the pushes onto the new stack: supervisor accesses, CS / CPL is loaded last)
    if v86:
        sq += [U(sec='PUSH', e='PASSB', sb='SEGF', rfix=r, sz='SEL', wr='SEC', sv=1) for r in (5, 4, 3, 0)]
        sq += [U(e='SEGNUL', rfix=r, sz='W16') for r in (3, 0, 4, 5)]
    sq += [U(sec='PUSH', e='PASSB', sb='T4', sz='SEL', wr='SEC', sv=1),
           U(sec='PUSH', e='PASSB', sb='T9', sz='Z', wr='SEC', sv=1)]
    if params:
        # copy the parameters (count from the gate) from the old stack, last one first
        sq += [U(e='PASSB', sb='T8', d1='T0', sz='D32', lp='X'),
               U(e='SUBNF', sa='T0', sb='OPSZ', d1='T0', sz='D32', label='top'),
               U(a='LIN', mrd=1, sec='PUSH', e='PASSB', sb='MEM', sz='Z', wr='SEC', goto='top', lp='X'),
               U(e='PASSB', sb='T6', d1='T0', sz='D32', label='X')]
    return sq
# call gate (E micro-jumps here from the far CALL / JMP; gate in T0 (selector) / T1 / T3,
# operand size = the gate's): target EIP to T2, its selector to T0
def gate_seq(ck, tail):
    return [U(e='GATE', sa='T1', sb='T3', d1='T2', d2='T0', sz='D32'),
            U(a='DSCT', aoff=0, mrd=1, e='DLO', ck=ck, sa='T0', sb='MEM', d1='T1', sz='D32'),
            U(a='DSCT', aoff=4, mrd=1, sec='DSCA', e='DHI', ck=ck, sa='T0', sb='MEM', d2='T3', sz='B', wr='SEC')] + tail
CALLG  = gate_seq('CGC', [U(sec='PUSH', e='PASSB', sb='CS', sz='Z', wr='SEC'),
                          U(sec='PUSH', e='LDCS', ck='CSC', sz='Z', wr='SEC')])
JMPG   = gate_seq('CGJ', [U(e='LDCS', ck='CSJ', sz='Z')])
CALLGI = stack_in(True) + [U(sec='PUSH', e='PASSB', sb='CS', sz='Z', wr='SEC', sv=1),
                           U(sec='PUSH', e='LDCS', ck='CGI', sz='Z', wr='SEC', sv=1)]
INTI   = stack_in(False, gate=False) + int_tail('INTI', sv=1, acc=False)
INTV   = stack_in(False, v86=True, gate=False) + int_tail('INTI', sv=1, acc=False)
# IRETD to V86 (CPL 0, VM in the popped EFLAGS in T4; EIP T2, CS T0): pop ESP, SS, ES, DS,
# FS, GS; the data segments are loaded V86 style at once, SS and ESP after the pops
IRETV  = ([U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T7', sz='Z'),
           U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T5', sz='Z')] +
          [U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='SEGF', rfix=r, ck='V86', sz='Z') for r in (0, 3, 4, 5)] +
          [U(e='PASSB', sb='T7', d1='FIX', rfix=4, sz='D32'),
           U(e='PASSB', sb='T5', d1='SSR', ck='V86', sz='W16'),
           U(e='LDV86', sb='T4', sz='D32')])
# Return to an outer level (RET / IRET micro-jump; EIP T2, CS T0 / T1 / T3, IRET: EFLAGS T4):
# pop (E)SP -> T7, SS -> T0, load SS (low dword in T5), (E)SP (+ imm16 of RET n), null the
# data segments not valid at the new CPL, load CS.
def ret_out(ck, flg):
    return ([U(e='PASSB', sb='T0', d1='T6', sz='D32'),
             U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T7', sz='Z'),
             U(a='POP', mrd=1, e='PASSB', sb='MEM', d1='T0', sz='Z'),
             U(a='DSCT', aoff=0, mrd=1, e='DLO', ck='RSS', sa='T0', sb='MEM', d1='T5', sz='D32'),
             U(a='DSCT', aoff=4, mrd=1, sec='DSCA', e='DHI', ck='RSS', sa='T0', sb='MEM', d1='SSR',
               sz='B', wr='SEC'),
             U(e='LDSP', ck='RSS', sa='IMM', sb='T7', d1='FIX', rfix=4, sz='D32'),   # (+ imm16 of RET n)
             U(e='PASSB', sb='T6', d1='T0', sz='D32'),
             U(a='DSCT', aoff=4, sec='DSCA', e='DHI', ck='ACC', sa='T0', sb='T3', sz='B', wr='SEC')] +
            [U(e='SEGVAL', rfix=r, sz='W16') for r in (3, 0, 4, 5)] +
            [U(e='LDCS', ck=ck, sb=('T4' if flg else 'ZERO'), sz='Z')])
RETO  = ret_out('CSR', False)
# ---- task switch
# entries: far JMP / CALL to a TSS (TSWD: T0 / T1 / T3 = its selector / descriptor) or a
# task gate (TASKG: gate in T0 / T1), INT through a task gate (TASKI: TSS selector in T0),
# IRET with NT (IRETT: the back link).  E keeps the kind (JMP / CALL / INT / IRET).
def ttss(a='DSCT'):
    return [U(a=a, aoff=0, mrd=1, e='DLO', ck='TTSS', sa='T0', sb='MEM', d1='T1', sz='D32'),
            U(a=a, aoff=4, mrd=1, e='DHI', ck='TTSS', sa='T0', sb='MEM', d2='T3', sz='D32')]
TASKG = [U(e='GATE', sa='T1', sb='T3', d2='T0', sz='D32')] + ttss()
TASKI = ttss()
IRETT = [U(a='TSSA', aoff=0, mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16')] + ttss()
# TSWS: save (old TSS layout: 386 / 286), busy bits, link, commit (E micro-jumps here from
# DHI TTSS, by the old TSS type)
def tsw_save(t32):
    eip, flg, gpr, sel = (0x20, 0x24, 0x28, 0x48) if t32 else (0x0E, 0x10, 0x12, 0x22)
    sz, st = ('D32', 4) if t32 else ('W16', 2)
    sq = [U(e='TSSDESC', sa='T0', d1='T8', sz='D32'),
          U(e='PASSB', sb='T0', d1='T6', sz='D32'),
          U(a='TSSA', aoff=eip, e='PASSB', sb='IPN', sz=sz, wr='PRI'),
          U(a='TSSA', aoff=flg, e='TFLG', sz=sz, wr='PRI')]
    sq += [U(a='TSSA', aoff=gpr + st * r, e='PASSB', sb='FIX', rfix=r, sz=sz, wr='PRI') for r in range(8)]
    sq += [U(a='TSSA', aoff=sel + st * k, e='PASSB', sb='SEGF', rfix=k, sz=sz, wr='PRI')
           for k in (range(6) if t32 else range(4))]
    sq += [U(a='DSCT', aoff=4, mrd=1, sec='DSCA', e='DHI', ck='TBSY', sa='T0', sb='MEM', sz='B', wr='SEC'),
           U(e='PASSB', sb='TRS', d1='T0', sz='W16'),
           U(a='DSCT', aoff=4, mrd=1, sec='DSCA', e='DHI', ck='TFRE', sa='T0', sb='MEM', sz='B', wr='SEC'),
           U(e='PASSB', sb='T8', d1='T0', sz='D32'),
           U(a='LIN', aoff=0, e='TLNK', sb='TRS', sz='W16', wr='PRI'),
           U(e='PASSB', sb='T6', d1='T5', sz='D32'),
           # the new EIP in both layouts (386: T2, 286: T7); LDTSK keeps the one of the new TSS in T2
           U(a='LIN', aoff=0x20, mrd=1, e='PASSB', sb='MEM', d1='T2', sz='D32'),
           U(a='LIN', aoff=0x0E, mrd=1, m16=1, e='PASSB', sb='MEM', d1='T7', sz='W16'),
           U(e='PASSB', sb='T5', d1='T0', sz='D32'),
           U(e='LDTSK', d1='T2', sz='D32')]
    return sq
# TSWL: load the new task (new TSS layout; E micro-jumped here at the new EIP, a fault is
# taken in the new task): CR3, EFLAGS, registers, selectors, then the LDT, CS, SS and data
# segment descriptors (#TS); V86 tasks: segments V86 style
def tsw_load(t32, v86=False):
    flg, gpr, sel, ldt = (0x24, 0x28, 0x48, 0x60) if t32 else (0x10, 0x12, 0x22, 0x2A)
    sz, st = ('D32', 4) if t32 else ('W16', 2)
    segs = range(6) if t32 else range(4)
    sq = ([U(a='TSSA', aoff=0x1C, mrd=1, e='LDCR3', sb='MEM', sz='D32')] if t32 else [])
    sq += [U(a='TSSA', aoff=flg, mrd=1, e='TLFL', sb='MEM', sz=sz)]
    if t32:
        sq += [U(a='TSSA', aoff=0x64, mrd=1, e='TBIT', sb='MEM', sz='B')]
    sq += [U(a='TSSA', aoff=gpr + st * r, mrd=1, m16=(0 if t32 else 1), e=('PASSB' if t32 else 'TLDW'), sb='MEM',
             d1='FIX', rfix=r, sz='D32') for r in range(8)]
    if v86:
        sq += [U(a='TSSA', aoff=sel + st * k, mrd=1, m16=1, e='PASSB', sb='MEM', d1='SEGF', rfix=k, ck='V86', sz='W16')
               for k in segs if k != 1]
        sq += [U(a='TSSA', aoff=ldt, mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16'),
               U(a='DSCT', aoff=0, mrd=1, e='DLO', ck='TLDT', sa='T0', sb='MEM', d1='T1', sz='D32'),
               U(a='DSCT', aoff=4, mrd=1, e='DHI', ck='TLDT', sa='T0', sb='MEM', sz='D32'),
               U(a='TSSA', aoff=sel + st, mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16'),
               # (EFLAGS image again from the TSS: the FLAGS operand source reads 0 here)
               U(a='TSSA', aoff=flg, mrd=1, e='LDV86', sb='MEM', sz='D32')]
        return sq
    sq += [U(a='TSSA', aoff=sel + st * k, mrd=1, m16=1, e='PASSB', sb='MEM', d1='SEGF', rfix=k, ck='SELO', sz='W16')
           for k in segs]
    if not t32:
        # a 286 TSS has no FS / GS: both null (80386 microcode LOAD_TASK_16: 0 -> FS, 0 -> GS)
        sq += [U(e='SEGNUL', rfix=r, sz='W16') for r in (4, 5)]
    sq += [U(a='TSSA', aoff=ldt, mrd=1, m16=1, e='PASSB', sb='MEM', d1='T0', sz='W16'),
           U(a='DSCT', aoff=0, mrd=1, e='DLO', ck='TLDT', sa='T0', sb='MEM', d1='T1', sz='D32'),
           U(a='DSCT', aoff=4, mrd=1, e='DHI', ck='TLDT', sa='T0', sb='MEM', sz='D32'),
           U(e='PASSB', sb='SEGF', rfix=1, d1='T0', sz='W16'),
           U(a='DSCT', aoff=0, mrd=1, e='DLO', ck='TCS', sa='T0', sb='MEM', d1='T1', sz='D32'),
           U(a='DSCT', aoff=4, mrd=1, e='DHI', ck='TCS', sa='T0', sb='MEM', d2='T3', sz='D32')]
    for k in [2] + [r for r in (3, 0, 4, 5) if r in segs]:
        ck = 'TSSS' if k == 2 else 'TDS'
        sq += [U(e='PASSB', sb='SEGF', rfix=k, d1='T0', sz='W16'),
               U(a='DSCT', aoff=0, mrd=1, e='DLO', ck=ck, sa='T0', sb='MEM', d1='T5', sz='D32'),
               U(a='DSCT', aoff=4, mrd=1, sec='DSCA', e='DHI', ck=ck, rfix=k, sa='T0', sb='MEM',
                 d1=('SSR' if k == 2 else 'SEGF'), sz='B', wr='SEC')]
    sq += [U(sec='PUSH', e='PASSB', sb='ERRC', sz='TSZ', wr='SEC', ifec=1),
           U(e='PASSB', sb='SEGF', rfix=1, d1='T0', sz='W16'),
           U(a='DSCT', aoff=4, sec='DSCA', e='DHI', ck='ACC', sa='T0', sb='T3', sz='B', wr='SEC'),
           U(e='LDCS', ck='TCS', sz=('D32' if t32 else 'W16'))]
    return sq
IRETO = ret_out('CSI', True)
# inject entry points (E selects one by id): their order is the inject id (tetrium_pkg.sv INJ_*, used by
# tetrium_exec.sv): add new ones at the end
INJ = [('INT_RM', INT_SEQ), ('INT_PM', INT_PM), ('INTF', INT_FRAME), ('CALLG', CALLG), ('JMPG', JMPG),
       ('CALLGI', CALLGI), ('INTI', INTI), ('RETO', RETO), ('IRETO', IRETO), ('INTV', INTV), ('IRETV', IRETV),
       ('TASKG', TASKG), ('TASKI', TASKI), ('IRETT', IRETT), ('TSWS32', tsw_save(True)), ('TSWS16', tsw_save(False)),
       ('TSWL32', tsw_load(True)), ('TSWL16', tsw_load(False)), ('TSWV86', tsw_load(True, True))]

# (the REP-exhausted retire marker needs no ROM entry: A turns a killed REP iteration
# into a RETIRE uop)

# ================================================================= undefined opcodes
# everything not defined raises #UD (filler entries: not counted by the microcode coverage
# report, tools/ucov.py)
def UDF():
    sq = UD()
    sq[0].fill = True
    return sq


for pg in (0, 1):
    for op in range(256):
        if (pg, op) in GROUPS:
            for mod3 in (0, 1):
                disp[(pg << 9) | (op << 1) | mod3] = UDF()     # (unused dispatch slot of a group opcode)
            for reg in range(8):
                for mod3 in (0, 1):
                    disp.setdefault(didx(pg, op, mod3, reg), UDF())
        else:
            for mod3 in (0, 1):
                disp.setdefault(didx(pg, op, mod3), UDF())
