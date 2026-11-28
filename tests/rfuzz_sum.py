#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""Summary of a tests/rfuzz.sh batch: mismatches grouped by signature (mode, paging, opcode,
injected or not, the fields that differ).  Failing seeds are appended to <dir>/fails.txt and
their files moved to <dir>/fail/; the files of passing seeds are deleted.

Usage: rfuzz_sum.py <dir> <first seed> <last seed> <nretire>
"""
import collections, os, re, sys

PFX = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}


def signature(tags, line):
    mode = tags[0] if tags else '?'
    if 'pg' in tags[1:2]:
        mode += '+pg'
    if '%Fatal' in line:
        m = re.search(r'%Fatal: (\S+:\d+)', line)
        return '%s ASSERT %s' % (mode, m.group(1) if m else '?')
    if 'LOCK MISMATCH' not in line:
        kind = 'TIMEOUT' if 'TIMEOUT' in line else 'HANG' if 'HANG' in line else line.split()[1] if len(line.split()) > 1 else '?'
        return '%s %s' % (mode, kind)
    first = line.split('first:', 1)[1] if 'first:' in line else line
    m = re.search(r'\[([0-9a-f ]+)\](.*)', first)
    if not m:       # (a whole-run message: shutdown, NMI, OUT bytes)
        return '%s %s' % (mode, re.sub(r'[0-9a-f]{4,}', '#', first.strip())[:60])
    bs = [int(x, 16) for x in m.group(1).split()]
    i = 0
    while i < len(bs) - 1 and bs[i] in PFX:
        i += 1
    op = '%02X' % bs[i] + ('%02X' % bs[i + 1] if bs[i] == 0x0F and i + 1 < len(bs) else '')
    rest = m.group(2)
    inj = ' inj' if rest.startswith(' (injected)') else ''
    fields = sorted(set(re.findall(r' ([a-z][a-z0-9.,]*)(?:\[[0-9a-f]+\])?=', rest)))
    return '%s op %s%s: %s' % (mode, op, inj, ' '.join(fields))


def main():
    d, s0, s1, nret = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    ok = early = 0
    groups = collections.OrderedDict()
    fails = []
    for s in range(s0, s1 + 1):
        base = os.path.join(d, 'run', 's%d' % s)
        try:
            tags = open(base + '.txt').read().split()
        except OSError:
            tags = []
        try:
            lines = [x for x in open(base + '.log').read().splitlines() if 'LOCK' in x or 'HANG' in x or 'ERR' in x]
            # (an RTL assertion ($fatal) stops the simulation before the LOCK line)
            lines += [x for x in open(base + '.log').read().splitlines() if '%Fatal' in x][:1]
        except OSError:
            lines = []
        line = lines[-1] if lines else 's%d.bin NOLOG (generator failed?)' % s
        if 'LOCK OK' in line:
            ok += 1
            m = re.search(r'insns=(\d+)', line)
            if m and int(m.group(1)) < nret:
                early += 1
            for ext in ('.bin', '.txt', '.log'):
                if os.path.exists(base + ext):
                    os.remove(base + ext)
            continue
        sig = signature(tags, line)
        groups.setdefault(sig, []).append(s)
        fails.append('%-8d %s | %s | %s' % (s, sig, ' '.join(tags), line.split('LOCK', 1)[-1].strip()[:300]))
        for ext in ('.bin', '.txt', '.log'):
            if os.path.exists(base + ext):
                os.replace(base + ext, os.path.join(d, 'fail', 's%d%s' % (s, ext)))
    with open(os.path.join(d, 'fails.txt'), 'a') as f:
        for x in fails:
            f.write(x + '\n')
    n = s1 - s0 + 1
    print('random-state fuzz, seeds %d-%d: OK %d / %d (%d of them ended early at a handler HLT)' % (s0, s1, ok, n, early))
    for sig, ss in sorted(groups.items(), key=lambda x: -len(x[1])):
        print('  %4d  %s   (seeds %s%s)' % (len(ss), sig, ' '.join(map(str, ss[:6])), ' ...' if len(ss) > 6 else ''))
    if fails:
        print('details: %s, files: %s' % (os.path.join(d, 'fails.txt'), os.path.join(d, 'fail')))


if __name__ == '__main__':
    main()
