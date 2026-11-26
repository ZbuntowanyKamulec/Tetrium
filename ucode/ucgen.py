#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""Microcode generator for the Tetrium core: assembles the microcode program and writes
the ROM image and the decoder tables.

    ucode/uarch.py      the micro-op: fields, their values and meaning, the ROM word layout
    ucode/microcode.py  the program: every instruction's micro-op sequence
    ucode/ucgen.py      this file: places the sequences in the ROM, writes the outputs

usage: ucode/ucgen.py [--check] [--list [FILE]] [--out DIR]
    (no option)   write the outputs to rtl/gen (make ucode)
    --check       generate in memory and compare with the files in rtl/gen: exit status 0
                  when identical (to verify a change to the generator that must not change
                  the microcode, such as a cleanup)
    --list [FILE] a readable listing of the ROM (default: stdout), one line per word
    --out DIR     write the outputs to DIR instead of rtl/gen

Outputs (rtl/gen):
    ucode_rom.hex     ROM image ($readmemh, UW_BITS wide, ROM_DEPTH deep)
    tetrium_pkg.sv    field layout + enum constants, inject and I/O entry tables
    ucode_class.svh   first-uop A-stage fields per opcode class, protected-mode dispatch
    modtab.svh        mod 9 / mod 17 tables (RCL / RCR counts)

Microcode model
---------------
Each macro instruction is one or more uops.  The ROM is indexed by a dispatch index for the
first uop of an instruction (microcode.py: didx); protected-mode sequences, inject entry
points and the I/O bitmap sequences are placed with the continuation uops and found through
decoder tables (pm_ent, inj_ent, io_ent).  Undefined entries raise #UD.

The A stage (address generation) cannot use ROM outputs directly (BRAM clock to out is too
slow), so every uop word carries the A-stage fields of its *successor* ("na_*").  The
A-stage fields of the first uop come from small LUT tables generated here (ucode_class.svh:
per opcode class and group).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from uarch import (ROM_DEPTH, UW_BITS, LAYOUT, AF_FIELDS, AF_BITS, WORD_USED, PRE_T,  # noqa: E402
                   AMODE, SEC, ABR, EOP, SRC, DST, ESZ, WR, CK, CHK, U, UcodeError, af_val, word,
                   SUPERVISOR_AMODES)
import microcode as mc                                                                    # noqa: E402
from microcode import GROUP_BASE, CONT_BASE, MR_SAME, didx, didx_name                     # noqa: E402,F401

OUT = os.path.join(HERE, '..', 'rtl', 'gen')
SPDX = '// SPDX-License-Identifier: GPL-3.0-or-later\n// Copyright (C) 2026 ZbuntowanyKamulec\n'
ROM_AW = (ROM_DEPTH - 1).bit_length()


# ------------------------------------------------------------------ assembler
class Image:
    """the placed microcode"""

    def __init__(self):
        self.rom = [None] * ROM_DEPTH
        self.next_free = CONT_BASE
        self.pm_ent = {}        # dispatch index -> first uop of the protected-mode sequence
        self.inj_addr = {}      # inject name -> ROM address
        self.iov_seq = {}       # opcode -> I/O bitmap sequence

    def alloc(self, n=1):
        """n consecutive continuation addresses (after the dispatch area)"""
        a = self.next_free
        self.next_free += n
        return a

    def place(self, seq, first_addr=None, org=None):
        """Place a sequence: first uop at first_addr (dispatch) or allocated, the others
        allocated; resolve goto / lp / 'self' into successors.  org: the sequence's name
        (listing, coverage, error messages; default: the dispatch opcode)."""
        if org is None:
            org = didx_name(first_addr)

        def fail(msg):
            raise UcodeError(f'{org}: {msg}')
        for i, (a, b) in enumerate(zip(seq, seq[1:])):
            if not b.goto and not a.goto:
                for t in PRE_T:
                    if (a.d1 == t or a.d2 == t) and (b.sa == t or b.sb == t):
                        fail(f'uop {i + 1} reads {t} right after uop {i} writes it ({", ".join(PRE_T)} '
                             'are read through the operand pre-select: one uop in between)')
        lab = {}
        for u in seq:
            if u.label:
                lab[u.label] = u
        for u in seq:
            for t in (u.goto, u.lp):
                if t and t not in lab:
                    fail(f'no uop labelled {t!r}')
        # micro-loop pairs: successor at an even address, exit uop right after it
        for i, u in enumerate(seq):
            if u.lp:
                n = lab[u.goto] if u.goto else seq[i + 1]
                x = lab[u.lp]
                if n is seq[0] or x is seq[0]:
                    fail('a micro-loop cannot continue or exit at the first uop')
                if x.af()[:4] != (0, 0, 0, 0):
                    fail(f'loop exit uop {x.label!r} must not use the A stage')
                if n.addr is None:
                    assert x.addr is None
                    if self.next_free & 1:
                        self.alloc()
                    n.addr = self.alloc(2)
                    x.addr = n.addr + 1
                if x.addr != n.addr + 1:
                    fail(f'loop exit uop {x.label!r} is not right after the loop successor')
        for i, u in enumerate(seq):
            if i == 0 and first_addr is not None:
                u.addr = first_addr
            elif u.addr is None:
                u.addr = self.alloc()
        for i, u in enumerate(seq):
            if u.goto:
                u.nxt = lab[u.goto]
            elif u.label == 'self' and u.endnr:
                u.nxt = u
            elif i + 1 < len(seq):
                u.nxt = seq[i + 1]
            else:
                u.nxt = None
            if u.nxt is None:
                u.last = 1
            self.rom[u.addr] = u
            u.orgs.append((org, i, len(seq)))


def assemble():
    """place the whole program (once; the uops of microcode.py are placed in place)"""
    global _image
    if _image is not None:
        return _image
    img = Image()
    for idx in sorted(mc.disp):
        img.place(mc.disp[idx], idx)
    for idx in sorted(mc.disp_pm):
        img.place(mc.disp_pm[idx], org='pm ' + didx_name(idx))
        img.pm_ent[idx] = mc.disp_pm[idx][0]
    for n, sq in mc.INJ:
        img.place(sq, org='inject ' + n)
        img.inj_addr[n] = sq[0].addr
    for op in sorted(mc.IOV):
        img.iov_seq[op] = mc.fresh(mc.IOV[op])
        img.place(img.iov_seq[op], org=f'I/O bitmap {op:02X}')
    if img.next_free > ROM_DEPTH:
        raise UcodeError(f'the microcode needs {img.next_free} words, the ROM has {ROM_DEPTH}')
    _image = img
    return img


_image = None


# ------------------------------------------------------------------ outputs
def classes(pg, limit):
    """class ids of (af(mod!=3), af(mod==3)) for the non-group opcodes of a page"""
    pairs, cls = [], {}
    for op in range(256):
        if (pg, op) in mc.GROUPS:
            continue
        pr = (af_val(mc.disp[didx(pg, op, 0)][0]), af_val(mc.disp[didx(pg, op, 1)][0]))
        if pr not in pairs:
            pairs.append(pr)
        cls[op] = pairs.index(pr)
    if len(pairs) > limit:
        raise UcodeError(f'page {pg}: {len(pairs)} first-uop A-field classes, the decoder table holds {limit}')
    return pairs, cls


def outputs(img, log=print):
    """the generated files: {name: text}"""
    hexw = (UW_BITS + 3) // 4
    files = {'ucode_rom.hex': ''.join('%0*x\n' % (hexw, word(u)) for u in img.rom)}
    int_entry = img.inj_addr['INT_RM']
    # ---- package
    L = []
    L.append('// Generated by ucode/ucgen.py -- do not edit')
    L.append('package tetrium_pkg;')
    L.append(f'  localparam int UW_BITS = {UW_BITS};')
    L.append(f'  localparam int ROM_DEPTH = {ROM_DEPTH};')
    L.append(f'  localparam int ROM_AW = {ROM_AW};')
    L.append(f'  localparam int GROUP_BASE = {GROUP_BASE};')
    L.append(f'  localparam int INT_ENTRY = {int_entry};')
    L.append(f'  localparam int AF_BITS = {AF_BITS};')
    for n, (p, w) in LAYOUT.items():
        L.append(f'  localparam int UW_{n.upper()}_L = {p}, UW_{n.upper()}_W = {w};')
    p = 0
    for n, w in AF_FIELDS:
        L.append(f'  localparam int AF_{n.upper()}_L = {p}, AF_{n.upper()}_W = {w};')
        p += w
    for pre, lst in (('AM', AMODE), ('SEC', SEC), ('ABR', ABR), ('E', EOP), ('S', SRC),
                     ('D', DST), ('SZ', ESZ), ('WR', WR), ('CK', CK), ('CHK', CHK)):
        for i, n in enumerate(lst):
            L.append(f'  localparam int {pre}_{n} = {i};')
    L.append(f'  localparam logic [AF_BITS-1:0] INT_FIRST_AF = {AF_BITS}\'d{af_val(mc.INT_SEQ[0])};')
    for i, (n, sq) in enumerate(mc.INJ):
        L.append(f'  localparam int INJ_{n} = {i};')
    L.append('  // I/O instructions with the permission bitmap check: {hit, ROM address, first-uop A fields}')
    L.append('  function automatic logic [ROM_AW+AF_BITS:0] io_ent(input logic [7:0] op);')
    L.append('    case (op)')
    for op, sq in sorted(img.iov_seq.items()):
        L.append(f"      8'h{op:02X}: return {{1'b1, {ROM_AW}'d{sq[0].addr}, {AF_BITS}'d{af_val(sq[0])}}};")
    L.append("      default: return '0;")
    L.append('    endcase')
    L.append('  endfunction')
    L.append('  // inject entry points: ROM address and first-uop A fields by id')
    L.append('  function automatic logic [ROM_AW+AF_BITS-1:0] inj_ent(input logic [4:0] id);')
    L.append('    case (id)')
    for i, (n, sq) in enumerate(mc.INJ):
        L.append(f"      5'd{i}: return {{{ROM_AW}'d{img.inj_addr[n]}, {AF_BITS}'d{af_val(sq[0])}}};")
    L.append("      default: return '0;")
    L.append('    endcase')
    L.append('  endfunction')
    L.append('endpackage')
    files['tetrium_pkg.sv'] = SPDX + '\n'.join(L) + '\n'
    # ---- compact first-uop A-field tables for the decoder
    #   opclass(op) / opclass0f(op): class id of (af(mod!=3), af(mod==3)) per page
    #   class_af(cls, mod3) / class0f_af(cls, mod3), grp_af({group, reg, mod3})
    C = ['// Generated by ucode/ucgen.py -- do not edit']
    for pg, fn, bits, limit in ((0, '', 5, 32), (1, '0f', 4, 15)):
        pairs, cls = classes(pg, limit)
        C += [f'function automatic logic [{bits-1}:0] opclass{fn}(input logic [7:0] op);', '  case (op)']
        byc = {}
        for op, c in cls.items():
            byc.setdefault(c, []).append(op)
        for c, ops in sorted(byc.items()):
            if c == 0:
                continue
            C.append('    ' + ', '.join(f"8'h{o:02X}" for o in ops) + f": opclass{fn} = {bits}'d{c};")
        C += [f"    default: opclass{fn} = {bits}'d0;", '  endcase', 'endfunction',
              f'function automatic logic [{AF_BITS-1}:0] class{fn}_af(input logic [{bits-1}:0] c, input logic m3);',
              '  case ({c, m3})']
        for c, (m, r) in enumerate(pairs):
            C.append(f"    {bits+1}'d{2*c}: class{fn}_af = {AF_BITS}'d{m};")
            C.append(f"    {bits+1}'d{2*c+1}: class{fn}_af = {AF_BITS}'d{r};")
        C += [f"    default: class{fn}_af = {AF_BITS}'d0;", '  endcase', 'endfunction']
        log(f'ucode: page {pg}: {len(pairs)} opcode classes')
    # protected-mode sequences: {hit, ROM address, first-uop A fields}, one table by
    # {page, opcode, mod3} and one by {group, reg, mod3} (selected by grp after the lookup)
    for fn, kb, sel in (('pm_ent_n', 10, lambda k: k < GROUP_BASE), ('pm_ent_g', 7, lambda k: k >= GROUP_BASE)):
        C += [f'function automatic logic [{ROM_AW + AF_BITS}:0] {fn}(input logic [{kb-1}:0] k);', '  case (k)']
        for k, v in sorted(img.pm_ent.items()):
            if sel(k):
                kk = k - GROUP_BASE if k >= GROUP_BASE else k
                C.append(f"    {kb}'d{kk}: {fn} = {{1'b1, {ROM_AW}'d{v.addr}, {AF_BITS}'d{af_val(v)}}};")
        C += [f"    default: {fn} = '0;", '  endcase', 'endfunction']
    log(f'ucode: {len(img.pm_ent)} protected-mode dispatch entries')
    C += [f'function automatic logic [{AF_BITS-1}:0] grp_af(input logic [6:0] k);   // {{group, reg, mod3}}',
          '  case (k)']
    for k in range(16 * 7):
        C.append(f"    7'd{k}: grp_af = {AF_BITS}'d{af_val(mc.disp[GROUP_BASE + k][0])};")
    C += [f"    default: grp_af = {AF_BITS}'d0;", '  endcase', 'endfunction']
    files['ucode_class.svh'] = SPDX + '\n'.join(C) + '\n'
    M = ['// Generated by ucode/ucgen.py -- do not edit']
    for m in (9, 17):
        M.append(f'function automatic logic [4:0] mod{m}(input logic [7:0] n);')
        M.append('  case (n)')
        for n in range(256):
            M.append(f"    8'd{n}: mod{m} = 5'd{n % m};")
        M.append(f"    default: mod{m} = 5'd0;")
        M.append('  endcase')
        M.append('endfunction')
    files['modtab.svh'] = SPDX + '\n'.join(M) + '\n'
    log(f'ucode: {img.next_free} words used, INT_ENTRY={int_entry}, fields={WORD_USED} bits')
    return files


# ------------------------------------------------------------------ listing
def describe(u):
    """the A-stage and E-stage parts of a uop, as text (fields at their defaults left out)"""
    a = []
    if u.a != 'NONE':
        a.append(u.a + (f'+{u.aoff:x}h' if u.aoff else ''))
    if u.mrd:
        a.append('rd16' if u.m16 else 'rd')
    if u.sec != 'NONE':
        a.append('sec=' + u.sec)
    if u.abr != 'NONE':
        a.append('br=' + u.abr)
    for f in ('repchk', 'ifec'):
        if getattr(u, f):
            a.append(f)
    if u.sv and u.a not in SUPERVISOR_AMODES:     # (implied by the system-table modes)
        a.append('sv')
    e = [u.e]
    for f, v in (('a', u.sa), ('b', u.sb)):
        if v != 'ZERO':
            e.append(f'{f}={v}')
    if u.d1 != 'NONE' or u.d2 != 'NONE':
        e.append('->' + (u.d1 if u.d2 == 'NONE' else f'{"" if u.d1 == "NONE" else u.d1},{u.d2}'))
    if u.wr != 'NONE':
        e.append('wr=' + u.wr)
    if u.sz != 'W0':
        e.append('sz=' + u.sz)
    if u.rfix or 'FIX' in (u.sa, u.sb, u.d1, u.d2) or 'SEGF' in (u.sb, u.d1):
        e.append(f'rfix={u.rfix}')
    for f, n in (('ck', 'NONE'), ('chk', 'NONE')):
        if getattr(u, f) != n:
            e.append(f'{f}={getattr(u, f)}')
    if u.repz:
        e.append('repz')
    return ' '.join(a), ' '.join(e)


def listing(img):
    L = ['; Tetrium microcode (ucode/ucgen.py --list)',
         f'; {img.next_free} of {ROM_DEPTH} words; filler #UD and prefix placeholder entries left out',
         ';',
         '; addr sequence            #   A stage (address, load / store, branch)  E stage (op a= b= ->d1,d2 ...)  successor',
         '; (rd: load, rd16: 16-bit load; a= b=: the sources, ->: the results R, R2; successor: next address,',
         ';  "end" = last uop of the instruction, "endnr" = the instruction may end here (REP))']
    nfill = 0
    for addr, u in enumerate(img.rom):
        if u is None:
            continue
        if u.fill:
            nfill += 1
            continue
        # the sequences holding this word (an "X m" / "X r" pair: "X")
        orgs = [o for o, _, _ in u.orgs]
        names = []
        for o in orgs:
            if o[-2:] in (' m', ' r') and o[:-1] + {'m': 'r', 'r': 'm'}[o[-1]] in orgs:
                o = o[:-2]
            if o not in names:
                names.append(o)
        pos = u.orgs[0][1]
        a, e = describe(u)
        if u.nxt is None:
            nx = 'end'
        elif u.nxt is u:
            nx = 'self'
        else:
            nx = f'{u.nxt.addr:03x}'
        flags = (' endnr' if u.endnr else '') + (f' lp->{u.lp}' if u.lp else '')
        name = names[0] + (f' (+{len(names) - 1})' if len(names) > 1 else '')
        L.append(f'{addr:03x}  {name:<20} {pos:>2}  {a:<40} {e:<46} {nx}{flags}')
        if len(names) > 1:
            L.append(f'     ; also: {", ".join(names[1:])}')
    L.append(f'; {nfill} filler / placeholder entries')
    return '\n'.join(L) + '\n'


# ------------------------------------------------------------------ main
def main(argv):
    out = OUT
    check = False
    lst = None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--check':
            check = True
        elif a == '--list':
            lst = '-'
            if i + 1 < len(argv) and not argv[i + 1].startswith('--'):
                lst = argv[i + 1]
                i += 1
        elif a == '--out':
            out = argv[i + 1]
            i += 1
        else:
            print(__doc__.split('usage:')[1].split('Outputs')[0].strip())
            return 2
        i += 1
    try:
        img = assemble()
        files = outputs(img, log=(lambda s: None) if (check or lst) else print)
    except UcodeError as e:
        print(f'ucgen: {e}', file=sys.stderr)
        return 1
    if lst:
        text = listing(img)
        if lst == '-':
            sys.stdout.write(text)
        else:
            with open(lst, 'w') as f:
                f.write(text)
    if check:
        bad = []
        for n, t in files.items():
            p = os.path.join(out, n)
            if not os.path.exists(p) or open(p).read() != t:
                bad.append(n)
        if bad:
            print(f'ucgen --check: differs from {os.path.relpath(out)}: {", ".join(bad)}')
            return 1
        print(f'ucgen --check: identical to {os.path.relpath(out)} ({", ".join(files)})')
        return 0
    if lst:
        return 0
    os.makedirs(out, exist_ok=True)
    for n, t in files.items():
        with open(os.path.join(out, n), 'w') as f:
            f.write(t)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
