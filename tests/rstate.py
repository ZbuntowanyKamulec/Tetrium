#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""Random starting-state generator for the lockstep fuzzer (tests/rfuzz.sh).

Usage: rstate.py <out.bin> <seed> [nretire]       (also writes <out>.txt: a one-line summary)

Each seed gives a random CPU state that a loader reaches through code, from real mode at
0100:0000 (no state is forced into either model), then the random code of tests/rgen386.py:
  - protected mode at CPL 0-3 with a 16- or 32-bit code segment, or virtual-8086 mode;
    paging on or off; random CR0 bits (WP AM NE MP EM TS CD), IOPL, AC, RF, TF, ID;
    DR0-DR3 breakpoints on code and data addresses
  - segments with random bases (not aligned, near the 4 GB wrap with paging), limits (small,
    near the offsets, 4 GB), expand-down, B / D, DPL / RPL, accessed bits; ESP near the
    stack's ends; a second LDT and GDT: the data segment registers are loaded from GDT A, then
    LGDT switches to GDT B, where some of those descriptors differ (caches that do not match
    the table); random test descriptors in the GDT and the LDT for the program's loads
  - with paging: random PDE / PTE bits (P, R/W, U/S, PCD, PWT, A, D), data pages from a
    shared 4 MB pool (aliased), code in frames of its own, read-only

Handlers (ring 0, 32-bit interrupt / trap gates, every vector):
  - faults (#DE #BR #UD #NM #TS #NP #SS #GP #MF #AC): resume at the next instruction start
    after the faulting one (a table, no stores; code pages are never writable, so nothing the
    program does changes the code)
  - #PF: P, U (and W on data pages) set in the PDE and the PTE, INVLPG, restart; a write to a
    code page or a fault on a page of the tables, handlers or loader resumes like a fault
  - #DB: RF set in the frame; other vectors (traps, INT n): IRET
  - #DF, or a fault in a handler (CS = the handlers'): CLI, HLT (the run ends; the models
    must agree up to there, as for a triple fault)

File: 'RST1' u32 seed, nretire, flags (bit 0: paging), cpte_lo, cpte_hi (physical range of the
code pages' PTEs: their accessed bits may be set by either model first, see tb_main.cpp),
nchunks, then nchunks x (u32 addr, u32 len, bytes).  The testbench fills the 16 MB with
pseudo-random bytes from the seed, places the chunks and starts at 0100:0000 in real mode.
"""
import bisect, os, random, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rgen386 as G         # noqa: E402  (the code under test; its globals are set per seed)

M = 0xFFFFFFFF
# physical memory map
LOADER, STAGE2 = 0x1000, 0x1200                # real-mode loader (CS 0100), 32-bit second stage
GDTRA, IDTR, GDTRB, LSSP, JMPP = 0x1100, 0x1108, 0x1110, 0x1118, 0x1120
GDTB, GDTA, GDTLIM = 0x60000, 0x80000, 0xB007
IDT, HND, COMMON, FMASK, SYSBM = 0x8C000, 0x8C800, 0x8D800, 0x8DC00, 0x8DC20
TSS, LDTA, LDTB, LDTLIM = 0x8E000, 0x8E800, 0x8F000, 0x7F
PD, TS, T0, TC1, TC2, TW = 0x90000, 0x91000, 0x92000, 0x93000, 0x94000, 0x95000
STK0 = 0x9FFF0                                 # ring-0 stack (TSS ESP0, the loader's)
NEXTTAB = 0xC0000                              # u16 next instruction start per code offset
CODEPH, POOL = 0x100000, 0x400000              # code frames / data frames (paging)
PTWIN = 0xFF800000                             # linear window onto PD .. TW
SEL_FLAT, SEL_HCODE, SEL_TSS, SEL_LDT, SEL_S0 = 0xA000, 0xA008, 0xA010, 0xA018, 0xA020
SYSPAGES = [0x01] + list(range(0x60, 0x6C)) + list(range(0x80, 0xA0)) + list(range(0xC0, 0xE0))
FAULTS = (0, 5, 6, 7, 10, 11, 12, 13, 16, 17)
ERRC = (8, 10, 11, 12, 13, 14, 17)
CS_, SS_, DS_, ES_, FS_, GS_ = 0x1000, 0x7000, 0x3000, 0xB000, 0x4000, 0x5000


def desc(base, lim, acc, fl):
    """8-byte descriptor; fl = G << 3 | D/B << 2"""
    return struct.pack('<HHBBBB', lim & 0xFFFF, base & 0xFFFF, (base >> 16) & 0xFF, acc,
                       ((lim >> 16) & 0xF) | (fl << 4), (base >> 24) & 0xFF)


def wrap(start, n):
    """the linear interval(s) of n bytes from start, modulo 4 GB"""
    if n <= 0:
        return []
    if start + n <= 1 << 32:
        return [(start, start + n)]
    return [(start, 1 << 32), (0, start + n - (1 << 32))]


class Asm:
    """bytes at an address, with rel32 jumps to labels"""
    def __init__(self, org):
        self.org, self.b, self.lab, self.fix = org, bytearray(), {}, []

    def __call__(self, *xs):
        for x in xs:
            self.b += bytes(x) if isinstance(x, (list, tuple, bytes, bytearray)) else bytes([x])

    def d(self, v):
        self.b += struct.pack('<I', v & M)

    def w(self, v):
        self.b += struct.pack('<H', v & 0xFFFF)

    def L(self, n):
        self.lab[n] = self.org + len(self.b)

    def j(self, op, n):          # op: [0xE9] or [0x0F, 0x8x]
        self(op)
        self.fix.append((len(self.b), n))
        self.b += b'\0' * 4

    def done(self):
        for pos, n in self.fix:
            self.b[pos:pos + 4] = struct.pack('<i', self.lab[n] - (self.org + pos + 4))
        return bytes(self.b)


class State:
    def __init__(self, seed, nret):
        self.seed, self.nret = seed, nret
        r = self.r = random.Random(seed * 1000003 + 0x5EED)
        self.v86 = r.random() < 0.2
        self.pg = r.random() < 0.5
        self.cpl = 3 if self.v86 else r.choice([0, 0, 0, 1, 2, 3, 3, 3, 3, 3])
        self.d32 = (not self.v86) and r.random() < 0.5
        self.chunks = []
        self.tags = []

    # ------------------------------------------------------------ random values
    def bits(self, p):
        return self.r.random() < p

    def rval(self):
        r = self.r
        k = r.random()
        if k < 0.15:
            return r.choice([0, 1, M, 0x7FFFFFFF, 0x80000000, 0xFFFF, 0x8000, 0x10000])
        return r.randrange(0x10000) if k < 0.5 else r.randrange(1 << 32)

    def allowed(self, ivs):
        """may a writable (or, without paging, any) segment cover these linear intervals?"""
        if not self.pg:
            return all(0x200000 <= a and b <= 0xF00000 for a, b in ivs)
        if self.cpl > 0:
            return True         # (user pages only: the rest faults, see the #PF handler)
        bad = [(0, 0x100000), (self.clo, self.chi), (PTWIN, PTWIN + 0x6000)]
        return not any(a < y and x < b for a, b in ivs for x, y in bad)

    def span(self, base, eff, down, big):
        if not down:
            return wrap(base, eff + 1)
        hi = M if big else 0xFFFF
        return wrap((base + eff + 1) & M, hi - eff) if eff < hi else []

    def baselim(self):
        """(base, 20-bit limit, G, effective limit, B)"""
        r = self.r
        g, big = 0, self.bits(0.5)
        k = r.random()
        if k < 0.35:
            lim = 0xFFFF
        elif k < 0.55:
            lim = r.randrange(0x10000)
        elif k < 0.65:
            lim = r.randrange(0x100)
        elif k < 0.75:
            lim = r.randrange(0x10000, 0x100000)
        elif k < 0.9:
            g, lim = 1, r.randrange(0x100)
        else:
            g, lim = 1, r.choice([0xFFFFF, r.randrange(0x100000)])
        eff = ((lim << 12) | 0xFFF) if g else lim
        if self.pg:
            k = r.random()
            if k < 0.4:
                base = r.randrange(0x100000, 0x40000000)
            elif k < 0.6:
                base = r.randrange(1 << 32)
            elif k < 0.8:
                base = (-r.randrange(1, 0x20000)) & M         # near the 4 GB wrap
            else:
                base = r.randrange(0x100000, 0x10000000) & ~0xFFF
        else:
            base = r.randrange(0x200000, 0xE00000)
        if self.bits(0.4):
            base &= ~0xF
        return base, lim, g, eff, big

    def dseg(self, kind):
        """a data / code descriptor for a data segment register: kind 'main' (DS ES FS GS:
        mostly valid at the program's CPL) or 'test' (anything, also not present / system)"""
        r = self.r
        for _ in range(200):
            base, lim, g, eff, big = self.baselim()
            if kind == 'main':
                t = r.choices(['rw', 'ro', 'dn', 'dnro', 'code', 'conf'], [70, 10, 10, 3, 4, 3])[0]
                dpl = r.randrange(self.cpl, 4) if self.bits(0.85) else r.randrange(4)
            else:
                t = r.choice(['rw', 'rw', 'ro', 'dn', 'dnro', 'code', 'conf', 'xo', 'sys', 'np'])
                dpl = r.randrange(4)
            ty = {'rw': 0x12, 'ro': 0x10, 'dn': 0x16, 'dnro': 0x14, 'code': 0x1A, 'conf': 0x1E,
                  'xo': 0x18, 'np': 0x12}.get(t, 0)
            if t == 'sys':
                ty = r.choice([0x1, 0x2, 0x3, 0x4, 0x9, 0xB, 0xC])
            acc = (0 if t == 'np' else 0x80) | (dpl << 5) | ty | (1 if t != 'sys' and self.bits(0.7) else 0)
            wr = t in ('rw', 'dn', 'np')
            if (wr or not self.pg) and not self.allowed(self.span(base, eff, t in ('dn', 'dnro'), big)):
                continue
            return desc(base, lim, acc, (g << 3) | (big << 2)), (base, eff, t, dpl)
        return desc(0x300000, 0xFFFF, 0x93 | (self.cpl << 5), 0), (0x300000, 0xFFFF, 'rw', self.cpl)

    # ------------------------------------------------------------ the state
    def build(self):
        r = self.r
        cpl = self.cpl
        # the code under test (rgen386 with this state's mode)
        G.PM, G.PG, G.V86, G.D32, G.IRQ = True, self.pg, self.v86, self.d32, False
        G.RING, G.R3 = (0, False) if self.v86 else (cpl, cpl > 0)
        G.SS = SS_ | (0 if self.v86 else cpl)
        G.DSEGS = [DS_, ES_, FS_, GS_, G.SS]
        G.PO, G.PA = (0.7, 0.6) if self.d32 else (0.3, 0.12)
        tst = [0x0000, 0x0003, 0xFFF8, 0xB00B]
        tst += [(i * 8) | r.randrange(4) for i in range(1, 12)]
        tst += [(r.randrange(20) * 8) | 4 | r.randrange(4) for _ in range(6)]        # LDT
        tst += [s | r.randrange(4) for s in (DS_, ES_, FS_, GS_)]
        G.TSTSEL = tst
        g = G.Gen(self.seed)
        code = g.build(0xC000)
        # code segment (16 / 32-bit, conforming at an outer ring sometimes, execute-only sometimes)
        if self.v86:
            cb, ceff = 0x10000, 0xFFFF
        else:
            if self.pg:
                pc = r.randrange(2, 0x3FC)
                cb = (pc << 22) + r.randrange(0x400000 - 0x11000)
            else:
                cb = 0x100000 + r.randrange(0xE0000)
            if self.bits(0.6):
                cb &= ~(0xF if self.bits(0.5) else 0xFFF)
            k = r.random()
            cg, clim = (0, 0xFFFF) if k < 0.6 else (0, r.randrange(0x200, 0x10000)) if k < 0.85 else (1, 0xFFFFF)
            ceff = ((clim << 12) | 0xFFF) if cg else clim
            conf = cpl > 0 and self.bits(0.15)
            cdpl = r.randrange(cpl + 1) if conf else cpl
            cacc = 0x80 | (cdpl << 5) | 0x18 | (4 if conf else 0) | (2 if self.bits(0.75) else 0) | 1
            self.csd = desc(cb, clim, cacc, (cg << 3) | (self.d32 << 2))
            self.tags += ['d32' if self.d32 else 'd16'] + (['conf'] if conf else []) + \
                         (['xo'] if not cacc & 2 else []) + (['climit'] if ceff < 0xFFFF else [])
        self.cb = cb
        self.clo, self.chi = cb & ~0xFFF, (cb + 0x10000 + 0xFFF) & ~0xFFF
        # resume table: the next instruction start (inside the code segment's limit) per offset
        st = sorted(s for s in g.starts if s <= min(ceff, 0xFFFF))
        first = st[0] if st else 0
        nt = bytearray(0x20000)
        for o in range(0x10000):
            i = bisect.bisect_right(st, o)
            struct.pack_into('<H', nt, 2 * o, st[i] if i < len(st) else first)
        self.put(NEXTTAB, nt)
        if self.pg:
            self.put(CODEPH + (cb & 0xFFF), code)
        else:
            self.put(cb, code)
        eip = 0 if self.bits(0.8) or not st else r.choice(st[:len(st) // 2 + 1])

        # segments
        gdt = bytearray(GDTLIM + 1)
        info = {}
        for s in (DS_, ES_, FS_, GS_):
            d, info[s] = self.dseg('main')
            gdt[s:s + 8] = d
        for i in range(1, 12):
            gdt[i * 8:i * 8 + 8] = self.dseg('test')[0]
        if not self.v86:
            gdt[CS_:CS_ + 8] = self.csd
            for _ in range(200):          # stack: writable, DPL = CPL; ESP near its ends often
                base, lim, sg, eff, big = self.baselim()
                down = self.bits(0.2)
                if self.allowed(self.span(base, eff, down, big)):
                    break
            else:
                base, lim, sg, eff, big, down = 0x300000, 0xFFFF, 0, 0xFFFF, 0, False
            gdt[SS_:SS_ + 8] = desc(base, lim, 0x93 | (cpl << 5) | (4 if down else 0), (sg << 3) | (big << 2))
            lo, hi = (0, eff) if not down else (eff + 1, M if big else 0xFFFF)
            if lo > hi:
                lo, hi = 0, 0xFFFF
            k = r.random()
            if cpl == 0 and k < 0.6:
                k = 0.9               # (ring 0: the program's stack is the handlers' too)
            if k < 0.25:
                esp = lo + r.randrange(12)
            elif k < 0.5:
                esp = hi + 1 - r.randrange(12)
            elif k < 0.6:
                esp = r.randrange(1 << 32)
            else:
                esp = lo + r.randrange(hi - lo + 1)
            if not big and self.bits(0.5):
                esp = (esp & 0xFFFF) | (r.randrange(0x10000) << 16)
            esp &= M & ~1
            self.tags += ['ss' + ('dn' if down else '') + ('32' if big else '16')]
        else:
            k = r.random()
            esp = r.choice([0, 2, 4, 0xFFFE, 0xFFFC]) if k < 0.3 else r.randrange(0x10000) & ~1
        gdt[SEL_FLAT:SEL_FLAT + 8] = desc(0, 0xFFFFF, 0x93, 0xC)
        gdt[SEL_HCODE:SEL_HCODE + 8] = desc(0, 0xFFFFF, 0x9B, 0xC)
        gdt[SEL_TSS:SEL_TSS + 8] = desc(TSS, 0xE8, 0x89, 0)
        gdt[SEL_LDT:SEL_LDT + 8] = desc(LDTA, LDTLIM, 0x82, 0)
        gdt[SEL_S0:SEL_S0 + 8] = desc(0, 0xFFFFF, 0x93, 0xC)
        gdtb = bytearray(gdt)
        gdtb[SEL_TSS + 5] = 0x8B
        gdtb[SEL_LDT:SEL_LDT + 8] = desc(LDTB, LDTLIM, 0x82, 0)
        nstale = 0
        for s in [DS_, ES_, FS_, GS_] + [i * 8 for i in range(1, 12)]:
            if self.bits(0.3):
                gdtb[s:s + 8] = self.dseg('main' if s >= 0x1000 else 'test')[0]
                nstale += s >= 0x1000
        if nstale and not self.v86:
            self.tags.append('stale%d' % nstale)
        self.put(GDTA, gdt)
        self.put(GDTB, gdtb)
        for base in (LDTA, LDTB):
            self.put(base, b''.join(self.dseg('test')[0] for _ in range(16)))
        # TSS (ring-0 stack, I/O permission bitmap for ports 0-3FF)
        tss = bytearray(0xE9)
        struct.pack_into('<IH', tss, 4, STK0, SEL_S0)
        struct.pack_into('<H', tss, 0x66, 0x68)
        for k in range(0x68, 0xE8):
            tss[k] = 0 if r.randrange(3) else r.randrange(256)
        tss[0xE8] = 0xFF
        self.put(TSS, tss)

        # flags, CR0, debug registers, registers
        fl = 0x2 | (r.randrange(0x1000) & 0x8D5) | (0x200 if self.bits(0.5) else 0) | (r.randrange(4) << 12)
        if self.bits(0.3):
            fl |= 0x40000
        if self.bits(0.2):
            fl |= 0x200000
        if cpl > 0 or self.v86:
            if self.bits(0.2):
                fl |= 0x10000
            if self.bits(0.05):
                fl |= 0x100
        if self.v86:
            fl |= 0x20000
        cr0 = 0x11 | (0x80000000 if self.pg else 0)
        for b, p in ((0x10000, 0.5), (0x40000, 0.5), (0x20, 0.5), (2, 0.3), (4, 0.15), (8, 0.2), (0x40000000, 0.2)):
            if self.bits(p):
                cr0 |= b
        drs, dr7 = [0, 0, 0, 0], 0
        dbases = [info[s][0] for s in (DS_, ES_, FS_, GS_)] if not self.v86 else [0x30000, 0x40000, 0x50000, 0xB0000]
        for i in range(4):
            if not self.bits(0.3):
                continue
            if self.bits(0.4):
                a, rw, ln = cb + r.choice(st[:200] or [0]), 0, 0
            else:
                rw, ln = r.choice([1, 3]), r.choice([0, 1, 3])
                a = (r.choice(dbases) + r.randrange(0x1000)) & ~ln
            drs[i] = a & M
            dr7 |= (1 << (2 * i + r.randrange(2))) | (((ln << 2) | rw) << (16 + 4 * i))
        if dr7 and self.bits(0.5):
            dr7 |= 0x300
        gpr = [self.rval() for _ in range(8)]
        gpr[4] = esp

        # IDT: 32-bit interrupt / trap gates to the stubs, DPL 3 mostly
        idt = bytearray(0x800)
        for v in range(256):
            off = HND + v * 16
            pres = v < 32 or not self.bits(1 / 40)
            acc = (0x80 if pres else 0) | ((3 if self.bits(0.75) else 0) << 5) | (0xE if self.bits(0.6) else 0xF)
            idt[v * 8:v * 8 + 8] = struct.pack('<HHBBH', off & 0xFFFF, SEL_HCODE, 0, acc, off >> 16)
        self.put(IDT, idt)
        self.handlers()

        # paging
        cpte = (0, 0)
        if self.pg:
            cpte = self.tables()

        # loader: real mode -> CR0 (PE, PG ...) -> 32-bit ring 0 -> the state
        a = Asm(LOADER)
        a(0xFA, 0x2E, 0x66, 0x0F, 0x01, 0x16)
        a.w(GDTRA - LOADER)
        a(0x2E, 0x66, 0x0F, 0x01, 0x1E)
        a.w(IDTR - LOADER)
        if self.pg:
            a(0x66, 0xB8)
            a.d(PD)
            a(0x0F, 0x22, 0xD8)
        a(0x66, 0xB8)
        a.d(cr0)
        a(0x0F, 0x22, 0xC0, 0x66, 0xEA)
        a.d(STAGE2)
        a.w(SEL_HCODE)
        ld = bytearray(a.done().ljust(GDTRA - LOADER, b'\x90'))
        ld += struct.pack('<HI', GDTLIM, GDTA) + b'\0\0' + struct.pack('<HI', 0x7FF, IDT) + b'\0\0'
        ld += struct.pack('<HI', GDTLIM, GDTB) + b'\0\0' + struct.pack('<IH', esp, SS_) + b'\0\0'
        ld += struct.pack('<IH', eip, CS_)
        self.put(LOADER, ld)
        a = Asm(STAGE2)
        a(0x66, 0xB8)
        a.w(SEL_FLAT)
        a(0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xE0, 0x8E, 0xE8, 0x66, 0xB8)
        a.w(SEL_S0)
        a(0x8E, 0xD0, 0xBC)
        a.d(STK0)
        a(0x66, 0xB8)
        a.w(SEL_LDT)
        a(0x0F, 0x00, 0xD0, 0x66, 0xB8)
        a.w(SEL_TSS)
        a(0x0F, 0x00, 0xD8)
        for i in range(4):
            if drs[i]:
                a(0xB8)
                a.d(drs[i])
                a(0x0F, 0x23, 0xC0 | (i << 3))
        if dr7:
            a(0xB8)
            a.d(dr7)
            a(0x0F, 0x23, 0xF8)

        def regs():
            for k in (0, 1, 2, 3, 5, 6, 7):
                a(0xB8 + k)
                a.d(gpr[k])
        if self.v86:
            for v in (GS_, FS_, DS_, ES_, SS_, esp, fl, CS_, eip):
                a(0x68)
                a.d(v)
            regs()
            a(0xCF)
        else:
            # (RPL <= DPL: the loads at ring 0 succeed)
            sels = [s | (r.randrange(info[s][3] + 1) if self.bits(0.3) else 0) for s in (DS_, ES_, FS_, GS_)]
            for s, m in zip(sels, (0xD8, 0xC0, 0xE0, 0xE8)):
                a(0x66, 0xB8)
                a.w(s)
                a(0x8E, m)
            a(0x2E, 0x0F, 0x01, 0x15)
            a.d(GDTRB)
            if cpl > 0:
                for v in (SS_ | cpl, esp, fl, CS_ | cpl, eip):
                    a(0x68)
                    a.d(v)
                regs()
                a(0xCF)
            else:
                a(0x68)
                a.d(fl)
                a(0x9D, 0x2E, 0x0F, 0xB2, 0x25)
                a.d(LSSP)
                regs()
                a(0x2E, 0xFF, 0x2D)
                a.d(JMPP)
        self.put(STAGE2, a.done())

        mode = 'v86' if self.v86 else 'pm%d' % cpl
        self.tags = [mode] + (['pg'] if self.pg else []) + self.tags
        for b, n in ((0x10000, 'wp'), (0x40000, 'am'), (0x20, 'ne'), (2, 'mp'), (4, 'em'), (8, 'ts'), (0x40000000, 'cd')):
            if cr0 & b:
                self.tags.append(n)
        for b, n in ((0x100, 'tf'), (0x40000, 'ac'), (0x10000, 'rf'), (0x200, 'if')):
            if fl & b:
                self.tags.append(n)
        self.tags.append('iopl%d' % ((fl >> 12) & 3))
        if dr7:
            self.tags.append('dr')
        self.tags.append('esp=%08x' % esp)
        return cpte

    def put(self, addr, b):
        self.chunks.append((addr, bytes(b)))

    def handlers(self):
        """stubs (16 bytes per vector) and the common part, 32-bit flat ring 0"""
        stubs = bytearray()
        for v in range(256):
            a = Asm(HND + v * 16)
            if v in ERRC and v != 14:
                a(0x83, 0xC4, 0x04)                             # add esp, 4  (the error code)
            a(0x50, 0xB8)                                       # push eax ; mov eax, v
            a.d(v)
            a.j([0xE9], 'c')
            a.lab['c'] = COMMON
            stubs += a.done().ljust(16, b'\xCC')
        self.put(HND, stubs)
        a = Asm(COMMON)
        a(0x83, 0xF8, 14)
        a.j([0x0F, 0x84], 'pf')
        a(0x83, 0xF8, 1)
        a.j([0x0F, 0x84], 'dbg')
        a(0x83, 0xF8, 8)
        a.j([0x0F, 0x84], 'stop')
        a(0x2E, 0x0F, 0xA3, 0x05)                               # bt cs:[FMASK], eax
        a.d(FMASK)
        a.j([0x0F, 0x83], 'ret')
        a(0x66, 0x81, 0x7C, 0x24, 0x08)                         # cmp word [esp+8], HCODE
        a.w(SEL_HCODE)
        a.j([0x0F, 0x84], 'stop')
        a(0x0F, 0xB7, 0x44, 0x24, 0x04, 0x2E, 0x0F, 0xB7, 0x04, 0x45)     # movzx eax, [esp+4] ; movzx eax, cs:[NT+eax*2]
        a.d(NEXTTAB)
        a(0x89, 0x44, 0x24, 0x04)                               # mov [esp+4], eax
        a.L('ret')
        a(0x58, 0xCF)
        a.L('dbg')
        a(0x81, 0x4C, 0x24, 0x0C)                               # or dword [esp+12], RF
        a.d(0x10000)
        a(0x58, 0xCF)
        a.L('stop')
        a(0xFA, 0xF4, 0xEB, 0xFC)
        # #PF: [esp] eax, [esp+4] error code, [esp+8] EIP, [esp+12] CS
        a.L('pf')
        a(0x53, 0x1E, 0x66, 0xBB)                               # push ebx ; push ds ; mov bx, FLAT ; mov ds, bx
        a.w(SEL_FLAT)
        a(0x8E, 0xDB, 0x0F, 0x20, 0xD0, 0x3D)                   # mov eax, cr2 ; cmp eax, 1 MB
        a.d(0x100000)
        a.j([0x0F, 0x83], 'hi')
        a(0x89, 0xC3, 0xC1, 0xEB, 0x0C, 0x2E, 0x0F, 0xA3, 0x1D)   # bt cs:[SYSBM], cr2 >> 12
        a.d(SYSBM)
        a.j([0x0F, 0x82], 'pskip')
        a.j([0xE9], 'fix')
        a.L('hi')
        a(0x3D)
        a.d(PTWIN)
        a.j([0x0F, 0x82], 'fix')
        a(0x3D)
        a.d(PTWIN + 0x6000)
        a.j([0x0F, 0x82], 'pskip')
        a.L('fix')
        a(0x89, 0xC3, 0xC1, 0xEB, 0x16, 0x83, 0x0C, 0x9D)       # or dword [PTWIN + pdi*4], 7
        a.d(PTWIN)
        a(0x07, 0x8B, 0x1C, 0x9D)                               # mov ebx, [PTWIN + pdi*4]
        a.d(PTWIN)
        a(0x81, 0xE3)
        a.d(0xFFFFF000)
        a(0x81, 0xC3)
        a.d(PTWIN - PD)
        a(0xC1, 0xE8, 0x0C, 0x25)                               # lea ebx, [table + pti*4]
        a.d(0x3FF)
        a(0x8D, 0x1C, 0x83, 0x0F, 0x20, 0xD0, 0x3D)
        a.d(self.clo)
        a.j([0x0F, 0x82], 'data')
        a(0x3D)
        a.d(self.chi)
        a.j([0x0F, 0x83], 'data')
        a(0xF6, 0x44, 0x24, 0x0C, 0x02)                         # code page: a write is skipped
        a.j([0x0F, 0x85], 'pskip')
        a(0x83, 0x0B, 0x05)
        a.j([0xE9], 'inv')
        a.L('data')
        a(0x83, 0x0B, 0x07)
        a.L('inv')
        a(0x0F, 0x01, 0x38, 0x1F, 0x5B, 0x58, 0x83, 0xC4, 0x04, 0xCF)     # invlpg [cr2] ; restart
        a.L('pskip')
        a(0x1F, 0x5B, 0x66, 0x81, 0x7C, 0x24, 0x0C)
        a.w(SEL_HCODE)
        a.j([0x0F, 0x84], 'stop')
        a(0x0F, 0xB7, 0x44, 0x24, 0x08, 0x2E, 0x0F, 0xB7, 0x04, 0x45)
        a.d(NEXTTAB)
        a(0x89, 0x44, 0x24, 0x08, 0x58, 0x83, 0xC4, 0x04, 0xCF)
        body = a.done()
        assert COMMON + len(body) <= FMASK, hex(len(body))
        fm = bytearray(32)
        for v in FAULTS:
            fm[v >> 3] |= 1 << (v & 7)
        sb = bytearray(32)
        for p in SYSPAGES:
            sb[p >> 3] |= 1 << (p & 7)
        self.put(COMMON, body.ljust(FMASK - COMMON, b'\xCC') + bytes(fm) + bytes(sb))

    def tables(self):
        """page directory and tables; returns the physical range of the code pages' PTEs"""
        r = self.r

        def pte(base, p=0.85, w=0.7, u=0.7):
            e = base | (1 if self.bits(p) else 0) | (2 if self.bits(w) else 0) | (4 if self.bits(u) else 0)
            for b, q in ((0x10, 0.1), (0x8, 0.1), (0x20, 0.5), (0x40, 0.5)):
                if self.bits(q):
                    e |= b
            return e
        t0 = [pte(POOL + i * 0x1000) for i in range(1024)]
        ts = list(t0)
        for p in range(256):
            if p in SYSPAGES or (not self.v86) or p < 0x10:
                ts[p] = (p << 12) | 0x63
            elif p < 0x21:                       # V86 code: never writable
                ts[p] = pte(p << 12, w=0, u=0.8) | 0x20
            else:
                ts[p] = pte(p << 12, u=0.8)
        tw = [0] * 1024
        for i in range(6):
            tw[i] = (PD + i * 0x1000) | 0x63
        pd = [0] * 1024
        for i in range(1024):
            pd[i] = T0 | (1 if self.bits(0.9) else 0) | (2 if self.bits(0.8) else 0) | (4 if self.bits(0.8) else 0) | \
                (0x20 if self.bits(0.5) else 0)
        pd[0] = TS | 0x23 | (4 if self.v86 or self.bits(0.5) else 0)
        pd[0x3FE] = TW | 0x23
        tc = {}
        if self.v86:
            cpte = (TS + 0x10 * 4, TS + 0x21 * 4)
        else:
            pcs = sorted({self.clo >> 22, (self.chi - 1) >> 22})
            for k, pc in enumerate(pcs):
                tc[pc] = list(t0)
                # (accessed set: 86Box may walk the next code page ahead of the DUT)
                pd[pc] = (TC1 + k * 0x1000) | 0x20 | (1 if self.bits(0.9) else 0) | (2 if self.bits(0.8) else 0) | \
                    (4 if self.bits(0.8) else 0)
            for j, lin in enumerate(range(self.clo, self.chi, 0x1000)):
                tc[lin >> 22][(lin >> 12) & 0x3FF] = pte(CODEPH + j * 0x1000, w=0, u=0.8 if self.cpl else 0.5)
            cpte = (TC1 + ((self.clo >> 12) & 0x3FF) * 4, TC1 + (len(pcs) - 1) * 0x1000 + (((self.chi - 1) >> 12) & 0x3FF) * 4 + 4)
        pk = lambda t: struct.pack('<1024I', *t)     # noqa: E731
        self.put(PD, pk(pd))
        self.put(TS, pk(ts))
        self.put(T0, pk(t0))
        for k, pc in enumerate(sorted(tc)):
            self.put(TC1 + k * 0x1000, pk(tc[pc]))
        self.put(TW, pk(tw))
        return cpte


def main():
    out, seed = sys.argv[1], int(sys.argv[2])
    nret = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
    s = State(seed, nret)
    cpte = s.build()
    with open(out, 'wb') as f:
        f.write(b'RST1' + struct.pack('<6I', seed, nret, int(s.pg), cpte[0], cpte[1], len(s.chunks)))
        for addr, b in s.chunks:
            f.write(struct.pack('<II', addr, len(b)) + b)
    with open(os.path.splitext(out)[0] + '.txt', 'w') as f:
        f.write(' '.join(s.tags) + '\n')


if __name__ == '__main__':
    main()
