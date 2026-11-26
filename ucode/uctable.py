#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""The microcode as a table: a readable view of ucode/microcode.py (the source), one row
per micro-op, one block per sequence (make ulist: build/ucode.uc).  The table can be parsed
back and checked against the program (--check).

Table format
------------
    ; comment (to the end of the line, anywhere)
    == <entry points>                ; a sequence starts: where it is entered
    label | A stage | E stage | flow   one row per uop, in order

Entry points (one header may list several: they get copies of the same sequence)
    8B  40-47          one-byte opcodes (both mod forms)      8B:m  8B:r   one form only
    0F.B6  0F.80-8F    0F page                                F7/6  0F.01/2   group opcode /reg
    pm 8E:m            the protected-mode sequence (CR0.PE, not V86) of the entries
    inject NAME        an inject entry point (microcode.py INJ)
    io E4 E5           I/O instruction with the permission bitmap check (IOV)

A stage (address generation)
    <amode>[+<hex>h]   address mode (uarch.AMODE) and its byte offset (system tables)
    rd  rd16           load the operand MEM (rd16: 16 bits whatever the operand size)
    sec=<x> br=<x>     secondary (store) address (uarch.SEC), branch (uarch.ABR)
    repchk ifec sv     REP count check, only with an error code, supervisor access (implied
                       by the system-table modes DSC*, IDT, TSS, TSSA, LIN)
E stage
    <op>               the operation (uarch.EOP), then:
    a=<src> b=<src>    its operands (uarch.SRC)
    ->d1  ->d1,d2  ->,d2   where its results R / R2 go (uarch.DST)
    sz=<x> wr=<x>      size (uarch.ESZ, default W0), store R (uarch.WR)
    rfix=<n> ck=<x> chk=<x> repz
Flow (default: the next row; the last row ends the instruction)
    goto <label>       successor        self   the uop repeats (string instructions)
    endnr              the instruction may end after this uop (REP)
    lp <label>         micro-loop on the decoder's count: exit to <label> when zero

usage: ucode/uctable.py --check FILE...    parse the tables, compare every sequence with the
                                           one microcode.py enters at the same place
       ucode/uctable.py --dump [FILE]      write the whole program of microcode.py as a table
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from uarch import U, UcodeError, AMODE                                    # noqa: E402
import microcode as mc                                                    # noqa: E402
from ucgen import describe                                                # noqa: E402

FIELDS = ('a', 'sec', 'repchk', 'abr', 'mrd', 'e', 'sa', 'sb', 'd1', 'd2', 'sz', 'wr', 'repz', 'label',
          'goto', 'endnr', 'rfix', 'm16', 'lp', 'aoff', 'ck', 'chk', 'ifec', 'sv')


# ------------------------------------------------------------------ parse
def opcodes(tok):
    """'40-47' / '0F.80-8F' / 'F7/6' / 'F6/0-1' -> [(page, opcode, reg)]"""
    pg = 0
    if tok.upper().startswith('0F.'):
        pg, tok = 1, tok[3:]
    reg = None
    if '/' in tok:
        tok, r = tok.split('/')
        reg = [int(x) for x in r.split('-')]
        reg = range(reg[0], reg[-1] + 1)
    lo, _, hi = tok.partition('-')
    ops = range(int(lo, 16), int(hi or lo, 16) + 1)
    return [(pg, op, r) for op in ops for r in (reg if reg is not None else [None])]


def entries(head):
    """header text -> [key]: ('rm' | 'pm', dispatch index) / ('inj', name) / ('io', opcode)"""
    t = head.split()
    if t[0] == 'inject':
        return [('inj', n) for n in t[1:]]
    if t[0] == 'io':
        return [('io', int(x, 16)) for x in t[1:]]
    tab = 'rm'
    if t[0] == 'pm':
        tab, t = 'pm', t[1:]
    keys = []
    for tok in t:
        tok, _, form = tok.partition(':')
        for pg, op, reg in opcodes(tok):
            if (pg, op) in mc.GROUPS and reg is None:
                raise UcodeError(f'{tok}: a group opcode needs /reg')
            for mod3 in ((0, 1) if not form else (0,) if form == 'm' else (1,)):
                keys.append((tab, mc.didx(pg, op, mod3, reg)))
    return keys


def row(text):
    """one uop row -> U"""
    label, a, e, flow = (x.strip() for x in (text.split('|') + ['', '', ''])[:4])
    kw = {}
    if label:
        kw['label'] = label
    for tok in a.split():
        m = re.fullmatch(r'(\w+)\+([0-9a-fA-F]+)h', tok)
        if m and m[1] in AMODE:
            kw['a'], kw['aoff'] = m[1], int(m[2], 16)
        elif tok in AMODE:
            kw['a'] = tok
        elif tok in ('rd', 'rd16'):
            kw['mrd'] = 1
            kw['m16'] = int(tok == 'rd16')
        elif tok in ('repchk', 'ifec', 'sv'):
            kw[tok] = 1
        elif tok.startswith(('sec=', 'br=')):
            k, v = tok.split('=')
            kw['abr' if k == 'br' else k] = v
        else:
            raise UcodeError(f'A stage: {tok!r}?')
    et = e.split()
    if et:
        kw['e'] = et[0]
    for tok in et[1:]:
        if tok.startswith('->'):
            d = tok[2:].split(',')
            kw['d1'] = d[0] or 'NONE'
            if len(d) > 1:
                kw['d2'] = d[1]
        elif tok == 'repz':
            kw['repz'] = 1
        elif '=' in tok:
            k, v = tok.split('=')
            k = {'a': 'sa', 'b': 'sb'}.get(k, k)
            if k not in ('sa', 'sb', 'sz', 'wr', 'rfix', 'ck', 'chk'):
                raise UcodeError(f'E stage: {tok!r}?')
            kw[k] = int(v) if k == 'rfix' else v
        else:
            raise UcodeError(f'E stage: {tok!r}?')
    ft = flow.split()
    while ft:
        t = ft.pop(0)
        if t in ('goto', 'lp'):
            kw[t] = ft.pop(0)
        elif t == 'self':
            kw['label'] = 'self'
        elif t == 'endnr':
            kw['endnr'] = 1
        else:
            raise UcodeError(f'flow: {t!r}?')
    return U(**kw)


def parse(path):
    """-> [(header, [key], [U])]"""
    seqs = []
    for n, line in enumerate(open(path), 1):
        line = line.split(';')[0].rstrip()
        if not line.strip():
            continue
        try:
            if line.startswith('=='):
                h = line[2:].strip()
                seqs.append((h, entries(h), []))
            else:
                if not seqs:
                    raise UcodeError('a uop row before the first == header')
                seqs[-1][2].append(row(line))
        except (UcodeError, ValueError, TypeError) as ex:
            raise UcodeError(f'{os.path.basename(path)}:{n}: {ex}') from None
    return seqs


# ------------------------------------------------------------------ write
def fmt_row(u):
    a, e = describe(u)
    flow = []
    if u.goto:
        flow.append(f'goto {u.goto}')
    if u.label == 'self':
        flow.append('self')
    if u.endnr:
        flow.append('endnr')
    if u.lp:
        flow.append(f'lp {u.lp}')
    label = u.label if u.label and u.label != 'self' else ''
    return f'{label:<5} | {a:<30} | {e:<46} | {" ".join(flow)}'.rstrip()


def program_seq(key):
    """the sequence microcode.py enters at key"""
    t, k = key
    if t == 'rm':
        return mc.disp[k]
    if t == 'pm':
        return mc.disp_pm[k]
    if t == 'inj':
        return dict(mc.INJ)[k]
    return mc.fresh(mc.IOV[k])


def key_name(key):
    t, k = key
    if t in ('rm', 'pm'):
        return ('pm ' if t == 'pm' else '') + mc.didx_name(k)
    return f'inject {k}' if t == 'inj' else f'io {k:02X}'


def same(u, v):
    return all(getattr(u, f) == getattr(v, f) for f in FIELDS)


def header(keys):
    """entry keys (same table kind) -> header text, opcodes merged into ranges"""
    t = keys[0][0]
    if t == 'inj':
        return 'inject ' + ' '.join(k for _, k in keys)
    if t == 'io':
        return 'io ' + ' '.join(f'{k:02X}' for _, k in keys)
    forms = {}
    for _, i in keys:
        forms.setdefault(i & ~1, set()).add(i & 1)
    toks = []
    for i, f in sorted(forms.items()):
        nm = mc.didx_name(i)[:-2]                 # '0F B6' / 'F7 /6'
        nm = nm.replace('0F ', '0F.').replace(' /', '/')
        toks.append(nm + ('' if len(f) == 2 else ':r' if 1 in f else ':m'))
    # opcode ranges: consecutive one-byte opcodes with the same form
    out = []
    for tk in toks:
        m = re.fullmatch(r'((?:0F\.)?)([0-9A-F]{2})(:[mr])?', tk)
        if out and m and isinstance(out[-1], list) and out[-1][0] == m[1] and out[-1][3] == m[3] \
                and int(m[2], 16) == out[-1][2] + 1:
            out[-1][2] += 1
            continue
        out.append([m[1], int(m[2], 16), int(m[2], 16), m[3]] if m else tk)
    s = []
    for o in out:
        if isinstance(o, list):
            r = f'{o[1]:02X}' + (f'-{o[2]:02X}' if o[2] != o[1] else '')
            s.append(f'{o[0]}{r}{o[3] or ""}')
        else:
            s.append(o)
    return ('pm ' if t == 'pm' else '') + ' '.join(s)


def dump():
    """the whole program as a table: one block per distinct sequence"""
    groups = {}
    order = []
    for t, tab in (('rm', mc.disp), ('pm', mc.disp_pm)):
        for i in sorted(tab):
            if tab[i][0].fill:
                continue
            order.append((t, i))
    order += [('inj', n) for n, _ in mc.INJ] + [('io', o) for o in sorted(mc.IOV)]
    for key in order:
        sq = program_seq(key)
        sig = (key[0] if key[0] in ('inj', 'io') else key[0],
               tuple(tuple(getattr(u, f) for f in FIELDS) for u in sq))
        if sig not in groups:
            groups[sig] = (sq, [])
        groups[sig][1].append(key)
    L = ['; Tetrium microcode as a table (ucode/uctable.py --dump of ucode/microcode.py)', ';',
         '; label | A stage                        | E stage                                        | flow']
    for sq, keys in groups.values():
        L.append('')
        L.append(f'== {header(keys)}')
        L += [fmt_row(u) for u in sq]
    return '\n'.join(L) + '\n'


# ------------------------------------------------------------------ main
def check(paths):
    nseq = nrow = nent = bad = 0
    for p in paths:
        for h, keys, uops in parse(p):
            nseq += 1
            nrow += len(uops)
            for key in keys:
                nent += 1
                try:
                    ref = program_seq(key)
                except KeyError:
                    print(f'{p}: == {h}: {key_name(key)}: microcode.py has no sequence there')
                    bad += 1
                    continue
                if len(ref) != len(uops) or not all(same(u, v) for u, v in zip(uops, ref)):
                    bad += 1
                    print(f'{p}: == {h}: {key_name(key)} differs from microcode.py')
                    for i in range(max(len(ref), len(uops))):
                        a = fmt_row(uops[i]) if i < len(uops) else '(none)'
                        b = fmt_row(ref[i]) if i < len(ref) else '(none)'
                        print(f'   {"  " if a == b else "!="} table: {a}\n   {"  " if a == b else "  "} prog : {b}')
    print(f'{nseq} sequences, {nrow} uop rows, {nent} entry points: '
          f'{"all the same as microcode.py" if not bad else f"{bad} differ"}')
    return 1 if bad else 0


if __name__ == '__main__':
    args = sys.argv[1:]
    try:
        if args[:1] == ['--check'] and len(args) > 1:
            sys.exit(check(args[1:]))
        if args[:1] == ['--dump']:
            t = dump()
            if len(args) > 1:
                open(args[1], 'w').write(t)
            else:
                sys.stdout.write(t)
            sys.exit(0)
    except UcodeError as ex:
        print(f'uctable: {ex}', file=sys.stderr)
        sys.exit(1)
    print(__doc__.split('usage:')[1].strip())
    sys.exit(2)
