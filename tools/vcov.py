#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""RTL line / branch coverage: the RTL blocks no simulation ran.

The coverage build (make sim COV=1: build/simcov, Verilator --coverage-line) writes the
counters of every simulation to VCOV_DIR/<pid>.dat at exit (tests/run.sh -c sets VCOV_DIR to
<out>/vcov).  This merges them (verilator_coverage) and lists, per RTL file, the lines with
a coverage point (an if / else arm, a case item, a block) that was never reached in any
instance.  Left out: the generated tables (rtl/gen) and the simulation-only code (`ifdef SIM /
UCOV blocks: checks and debug outputs).

usage: tools/vcov.py [-a] DIR...      -a: include rtl/gen and the simulation-only code
"""
import glob, os, re, subprocess, sys
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


def sim_only_lines(path):
    """line numbers inside `ifdef SIM / `ifdef UCOV blocks (their `else part excluded)"""
    out, stack = set(), []
    try:
        lines = open(os.path.join(ROOT, path)).read().split('\n')
    except OSError:
        return out
    for n, l in enumerate(lines, 1):
        t = l.strip()
        m = re.match(r'`(ifdef|ifndef)\s+(\w+)', t)
        if m:
            stack.append(m[1] == 'ifdef' and m[2] in ('SIM', 'UCOV'))
        elif t.startswith('`else') and stack:
            stack[-1] = False
        elif t.startswith('`endif') and stack:
            stack.pop()
            out.add(n)
            continue
        if any(stack):
            out.add(n)
    return out


def main():
    args = sys.argv[1:]
    show_all = '-a' in args
    dirs = [a for a in args if a != '-a']
    if not dirs:
        print(__doc__.strip().splitlines()[-1]); sys.exit(2)
    files = [f for d in dirs for f in glob.glob(os.path.join(d, '*.dat'))]
    if not files:
        print(f'RTL coverage: no coverage files in {" ".join(dirs)}'); return
    merged = os.path.join(dirs[0], 'merged.dat.out')
    # (verilator_coverage reads the file list in batches: the command line stays short)
    for i in range(0, len(files), 200):
        part = files[i:i + 200] + ([merged] if i else [])
        subprocess.run(['verilator_coverage', '--write', merged + '.tmp'] + part, check=True,
                       stdout=subprocess.DEVNULL)
        os.replace(merged + '.tmp', merged)
    # points: (file, line, kind) -> count, summed over instances
    pts = defaultdict(int)
    for l in open(merged, errors='replace'):
        if not l.startswith('C '):
            continue
        key, cnt = l[3:].rsplit("' ", 1)
        kv = dict(x.split('\x02', 1) for x in key.split('\x01') if '\x02' in x)
        f = os.path.relpath(os.path.join(ROOT, kv.get('f', '?')), ROOT)
        pts[(f, int(kv.get('l', 0)), kv.get('o', ''))] += int(cnt)
    simo = {}
    byfile = defaultdict(lambda: [0, 0, defaultdict(list)])
    for (f, ln, kind), c in pts.items():
        if not show_all:
            if f.startswith('rtl/gen/'):
                continue
            if f not in simo:
                simo[f] = sim_only_lines(f)
            if ln in simo[f]:
                continue
        b = byfile[f]
        b[0] += 1
        if c == 0:
            b[1] += 1
            b[2][ln].append(kind)
    tot = sum(b[0] for b in byfile.values())
    miss = sum(b[1] for b in byfile.values())
    print(f'RTL coverage: {tot - miss} / {tot} points reached, {miss} never '
          f'({len(files)} simulations{"" if show_all else "; rtl/gen and simulation-only code left out"})')
    for f in sorted(byfile):
        n, m, lines = byfile[f]
        print(f'  {f:<28} {n - m:>5} / {n:<5} {100.0 * (n - m) / n:5.1f} %')
    for f in sorted(byfile):
        n, m, lines = byfile[f]
        if not m:
            continue
        try:
            src = open(os.path.join(ROOT, f)).read().split('\n')
        except OSError:
            src = []
        print(f'\n{f}: {m} points never reached (line: kind  source)')
        for ln in sorted(lines):
            kinds = ','.join(sorted(set(lines[ln])))
            text = src[ln - 1].strip() if 0 < ln <= len(src) else ''
            print(f'  {ln:>5}: {kinds:<10} {text[:110]}')


if __name__ == '__main__':
    main()
