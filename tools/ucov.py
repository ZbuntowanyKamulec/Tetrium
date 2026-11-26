#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""Microcode coverage: the ROM entries no simulation ran.

The testbench (built with UCOV, the default `make sim`) records the ROM address of every uop
that completes in E and, with UCOV_DIR set, writes them to UCOV_DIR/<pid>.txt at exit
(tests/run.sh sets it to <out>/ucov). This merges those files and lists the entries that were
never run, by sequence, against the microcode (ucode/microcode.py, placed by ucode/ucgen.py).

Counted: every position of every placed sequence, except the filler #UD entries of undefined
opcodes and the placeholder entries of the prefix bytes (never dispatched). The two dispatch entries of an opcode defined with one sequence for both mod forms
(no modrm: the decoder takes mod from the next byte) count once, as "B8"; a position is run
when any ROM address holding it was. Skipped uops (an error-code push without one) and killed
REP iterations do not count as run.

usage: tools/ucov.py [-a] DIR...      -a: also list the sequences that were run in full
"""
import contextlib, glob, io, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'ucode'))
with contextlib.redirect_stdout(io.StringIO()):
    import ucgen


def main():
    args = sys.argv[1:]
    show_all = '-a' in args
    dirs = [a for a in args if a != '-a']
    if not dirs:
        print(__doc__.strip().splitlines()[-1]); sys.exit(2)
    hit, nfiles = set(), 0
    for d in dirs:
        for fn in glob.glob(os.path.join(d, '*.txt')):
            nfiles += 1
            with open(fn) as f:
                hit.update(int(x, 16) for x in f.read().split())
    mr = {('pm ' if pm else '') + ucgen.didx_name(i) for pm, i in ucgen.MR_SAME}
    # entries: (sequence name, position) -> [uop, ROM addresses, run]
    ent, slen = {}, {}
    for a, u in enumerate(ucgen.assemble().rom):
        if u is None or u.fill:
            continue
        for org, pos, n in u.orgs:
            if org in mr or (org.endswith(' r') and org[:-1] + 'm' in mr):
                org = org[:-2]
            e = ent.setdefault((org, pos), [u, [], False])
            e[1].append(a)
            e[2] = e[2] or a in hit
            slen[org] = n
    nrun = sum(1 for e in ent.values() if e[2])
    print(f'microcode coverage: {nrun} / {len(ent)} entries run, {len(ent) - nrun} not run '
          f'({nfiles} simulations; filler #UD and prefix entries not counted)')
    if not nfiles:
        return

    def key(name):          # dispatch opcodes first, then pm, inject, I/O bitmap sequences
        return ({'pm': 1, 'inject': 2, 'I/O': 3}.get(name.split()[0], 0), name)
    never, partial = [], []
    for name in sorted(slen, key=key):
        n = slen[name]
        pos = [p for p in range(n) if (name, p) in ent]
        miss = [p for p in pos if not ent[(name, p)][2]]
        if not miss:
            if show_all:
                partial.append(f'  {name:<20} all {n} run')
            continue
        u0 = ent[(name, pos[0])][0]
        desc = u0.e + (f' ({u0.ck})' if u0.ck != 'NONE' else '')
        if len(miss) == len(pos):
            never.append(f'  {name:<20} {n:>2} uop{"s" if n > 1 else " "}  {desc}')
        else:
            um = ' '.join(f'{p}:{ent[(name, p)][0].e}@{ent[(name, p)][1][0]:03x}' for p in miss)
            partial.append(f'  {name:<20} {len(pos) - len(miss):>2} / {n:<2} run; not run: {um}')
    if never:
        print(f'never entered ({len(never)} sequences; first uop E op):')
        print('\n'.join(never))
    if partial:
        print('entered, some uops not run (position:E op@ROM address):')
        print('\n'.join(partial))


if __name__ == '__main__':
    main()
