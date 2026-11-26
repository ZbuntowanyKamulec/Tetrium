# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 ZbuntowanyKamulec
"""The Tetrium micro-op: its fields, their encodings and the ROM word layout.

A micro-op (uop) is written as U(field=value, ...); fields left out take their defaults
(see U below).  Each enumerated field takes a name from one of the tables in this file
(AMODE, SEC, ABR, EOP, SRC, DST, ESZ, WR, CK, CHK); a name's position in its table is its
encoding, so new names go at the end.  The meaning of each name is given next to it; the
hardware side is in rtl/tetrium_agu.sv (A stage) and rtl/tetrium_exec.sv (E stage).

ROM word (UW_BITS wide, FIELDS below, LSB first): the uop's own E-stage fields, plus the
A-stage fields of its successor ("na_*", look-ahead: the A stage cannot wait for the ROM
output) and the successor's address ("next").
"""
import textwrap

ROM_DEPTH = 2048
UW_BITS = 88


class UcodeError(Exception):
    pass


class Enum:
    """The names of an encoded field in encoding order (code = position), each with its
    meaning.  Built from a table: one name per line followed by its description; indented
    lines continue the description."""

    def __init__(self, field, table):
        self.field = field
        self.names, self.doc = [], {}
        for line in textwrap.dedent(table).strip('\n').splitlines():
            if not line.strip():
                continue
            if line[0] in ' \t':
                self.doc[self.names[-1]] += ' ' + line.strip()
            else:
                n, _, d = line.partition(' ')
                assert n not in self.doc, (field, n)
                self.names.append(n)
                self.doc[n] = d.strip()

    def code(self, name, field=None):
        try:
            return self.names.index(name)
        except ValueError:
            raise UcodeError(f'{field or self.field}={name!r}: not a known value '
                             f'(one of {", ".join(self.names)})') from None

    def __iter__(self):
        return iter(self.names)

    def __len__(self):
        return len(self.names)

    def __contains__(self, name):
        return name in self.doc


# ------------------------------------------------------------------ A stage
AMODE = Enum('a', '''
NONE   no memory address
EA     modrm / moffs / XLAT effective address, segment default / override
EA2    EA + operand size (the selector of a far pointer; 0F 01: + 2); never the first uop of a
       sequence (its displacement is registered from the instruction's fields)
POP    SS:(E)SP, (E)SP += size
POPN   SS:(E)SP, (E)SP += size + imm16 (RET n)
SI     segment (DS / override):(E)SI, (E)SI += +-size
DI     ES:(E)DI, (E)DI += +-size (primary address: a load)
VEC    IDTR base + imm8 * 4 (real-mode vector: offset)
VEC2   IDTR base + imm8 * 4 + 2 (real-mode vector: segment)
EAC    EA computed, no memory access (LEA)
TA     offset = T0 (computed by an earlier uop), segment as for EA
TAS    offset = T0, segment SS, stack address size
DSCR   system table: descriptor of the selector in the modrm r/m register: GDT or LDT (selector
       TI) base + (selector & FFF8) + aoff (0 / 4); linear, no segment limit check (the table
       limits are checked by the E uops)
DSCI   system table: descriptor of the selector in the immediate (as DSCR)
DSCT   system table: descriptor of the selector in T0 (as DSCR)
IDT    IDTR base + vector * 8 + aoff
TSS    TR base + T0 + aoff
LIN    linear address T0 + aoff
TSSA   TR base + aoff (unscaled)
''')
SEC = Enum('sec', '''
NONE   no secondary (store) address
PUSH   SS:(E)SP - size, (E)SP -= size
STDI   ES:(E)DI, (E)DI += +-size
DSCA   the access byte of the descriptor of a DSC* mode: table base + (selector & FFF8) + 5
''')
ABR = Enum('abr', '''
NONE   no branch
JMPD   direct, always taken, resolved in A (JMP rel, CALL rel)
LOOP   (E)CX -= 1, taken if not zero, resolved in A
LOOPZ  (E)CX -= 1, resolved in E (needs ZF)
LOOPNZ (E)CX -= 1, resolved in E (needs ZF)
JCXZ   resolved in A
BRE    Jcc: direct target, resolved in E
BRI    indirect near (JMP / CALL r/m, RET) and real-mode / V86 far transfers (JFAR: predicted
       when CS does not change), target from E
''')

# ------------------------------------------------------------------ E stage
EOP = Enum('e', '''
NOP     no operation in E (the uop may still use the A stage: address, push / pop, branch)
ALUOP   ALU operation from opcode[5:3] (ADD OR ADC SBB AND SUB XOR CMP): R = A op B, flags
ALUREG  ALU operation from modrm.reg (80-83)
ADD     R = A + B, flags (not used by the microcode)
SUB     R = A - B, flags (not used by the microcode)
TEST    flags of A AND B
INC     R = A + 1, flags (CF unchanged)
DEC     R = A - 1, flags (CF unchanged)
NOT     R = NOT A
NEG     R = 0 - A, flags
PASSA   R = A
PASSB   R = B
XCHG    R = B, R2 = A
SHIFT   rotate / shift (C0 C1 D0-D3, operation modrm.reg; count imm8 / 1 / CL) of A
MUL     MUL / IMUL (modrm.reg) of the accumulator A by B, result to the accumulator (and DX / EDX)
DIV     DIV / IDIV (modrm.reg) of the accumulator (and DX / EDX) by B; #DE
AAM     AAM on the accumulator (A), base imm8; #DE
AAD     AAD on the accumulator (A), base imm8
DAA     DAA on AL (A)
DAS     DAS on AL (A)
AAA     AAA on AX (A)
AAS     AAS on AX (A)
CBW     CBW / CWDE on the accumulator (A)
CWD     CWD / CDQ on the accumulator (A)
SALC    AL = CF ? FF : 00
LAHF    AH = the low flags byte
SAHF    the low flags byte = AH (A)
POPF    EFLAGS = B (the popped image; IOPL / IF / VM rules)
PUSHF   R = the flags image (pushed)
FLAGOP  CLC / STC / CMC / CLD / STD / CLI / STI by opcode
JCC     Jcc, condition opcode[3:0] (with ABR BRE)
LOOPCC  LOOPZ / LOOPNZ condition: ZF and (E)CX != 0
JNEAR   (E)IP = A, R = ip_next (pushed if wr)
JFAR    CS = A, (E)IP = B, R = ip_next (real mode / V86)
IRET    FLAGS = MEM, CS = T1, (E)IP = T0 (real mode / V86)
IN      R = input from port A (size of the instruction)
OUT     output B to port A
HLT     halt until an interrupt
INT     INT n / INT3 (vector imm8 / 3): starts the delivery
INTO    INT 4 if OF
INTFL   R = the flags image, IF = TF = 0 (real-mode interrupt frame)
LEA     R = the effective address (EAC)
CMP     flags of A - B; R2 = B (CMPXCHG: the destination's old value)
RETIRE  no-op marker that ends an instruction (REP exhaustion; A makes it, no ROM entry)
UD      invalid opcode (#UD fault)
MOVX    zero / sign extend B (byte or word, by op[0]) to the operand size (sign: op[3])
SETCC   R = condition opcode[3:0] (0 / 1)
BSWAP   R = A with its bytes reversed
IMUL2   R = A * B (signed, truncated), CF = OF = overflow
BOUND   #BR if A < B (signed)
BT      CF = bit (B mod size) of A; R = A with the bit set / reset / complemented
BTADR   R = EA + (bit offset B >> 3, operand aligned) (bit string address)
BSF     bit scan of B (forward / reverse by op[0]); R = index, or A if B = 0
SHXD    SHLD / SHRD of A with B, count imm8 / CL
XADD    R = A + B, R2 = A
CSEL    R = ZF ? B : A
SUBNF   R = A - B, no flags
ADDNF   R = A + B, no flags
SRD     R = system register (rfix: 0 CR0 / MSW, 1 GDTR.limit, 2 GDTR.base, 3 IDTR.limit,
        4 IDTR.base, 5 LDTR, 6 TR, 7 CR[modrm.reg])
SWR     system register write, then refetch (rfix: 0 LMSW from B, 1 CLTS, 2 GDTR {limit T1,
        base B}, 3 IDTR {limit T1, base B}, 7 CR[modrm.reg] = B)
ESC     coprocessor escape / WAIT without an FPU: #NM if CR0.EM / TS (WAIT: MP and TS)
DLO     descriptor low dword: R = B (memory), R2 = A (selector); table limit / null checks of
        check kind ck
DHI     descriptor high dword B, low dword in T1, selector A: type / privilege / present checks
        of kind ck; d1 = SEG loads the segment register (c_sreg); the store (wr = SEC, DSCA)
        sets the accessed bit (skipped if already set); R = B
LDCS    CS = descriptor {T1, T3} with selector T0, EIP = T2 (kind ck), redirect
EFL     R = the EFLAGS image (VM, RF included), no flag change (interrupt frames)
GATE    call gate low dword A, high dword B: R = the target EIP, R2 = the target selector (E keeps
        the parameter count)
TSSOFF  R = offset of SS:ESP for the privilege level of the code segment descriptor's DPL (A = its
        high dword) in the TSS; #TS if beyond the TSS limit
LDSP    (E)SP = B (+ imm16 of RET n: ck = RSS), at the size of the new stack (SS.B)
OLDSP   R = (E)SP at the stack size
SSB     R = the SS base (before the stack switch: the linear address of the call gate's
        parameters is summed in the ALU, with GPSZ)
SEGVAL  the data segment register rfix is loaded with null unless valid at the new CPL (RPL of
        T6): return to an outer level
IOMAP   R = I/O map base (B) + port (A) / 8; #GP(0) for a 286 TSS at CPL > IOPL
IOBIT   #GP(0) if a bit of the port (A, size of the instruction) is set in the map word B (map
        offset T0) or the bits lie beyond the TSS limit
LARV    LAR / LSL / VERR / VERW (ck) of the selector A, descriptor high dword B, low dword T1:
        ZF; LAR / LSL write the register only if valid
ARPL    ARPL r/m (A), r (B): R = A with RPL raised, ZF; no write if unchanged
IRVM    R = B (the popped EFLAGS); IRETD at CPL 0 with VM set micro-jumps to the V86 return
LDV86   V86 return: CS = T0 (real-mode style), EIP = T2[15:0], EFLAGS = B (VM), CPL 3
SEGNUL  segment register rfix = null (interrupt from V86, FS / GS of a 286 TSS)
IRNT    IRET with NT micro-jumps to the task return
TSSDESC R = the new TSS's base (T1 / T3), #TS if its limit is too small
TFLG    R = the EFLAGS image to save (NT cleared for IRET)
TLNK    the back-link store (CALL / INT only)
LDTSK   TR = T0 / T1 / T3 (busy), CR0.TS, micro-jump to the load part at the new EIP (T2)
LDCR3   CR3 = B
TLFL    EFLAGS = B (all bits, VM; NT for CALL / INT)
TLDW    R = B | FFFF0000
INVLPG  drop the TLB entry of the operand's linear address (serializing)
TRD     MOV r32, DRn / TRn (op[2]: TR; TR6 / TR7: TLB test, TR3-5: registers; #UD below TR3)
TWR     MOV DRn / TRn, r32
PROBE   a store uop that stores nothing: its address is checked for a write (limit, rights,
        paging: #SS / #GP / #PF) and translated with write intent
CPUID   R = register rfix (0 EAX, 1 ECX, 2 EDX, 3 EBX) of CPUID leaf A (#UD without CPUID)
CINV    INVD / WBINVD: store buffer drained, both caches invalidated (tag sweep), refetch
TBIT    the debug trap bit T = B[0] (386 TSS byte 64h: a #DB trap after the task switch)
RPROBE  a load uop that loads nothing: its address is limit / rights checked for a read (#SS /
        #GP), not translated, not read, no #AC
''')
SRC = Enum('sa / sb', '''
ZERO   0
REG    the register of modrm.reg
RM     the register of modrm.r/m
MEM    the memory operand (loaded by this uop: mrd)
ACC    the accumulator (AL / AX / EAX)
IMM    the immediate (direct far JMP / CALL: the selector)
OPR    the register of opcode[2:0]
T0     temporary register
T1     temporary register
SEG    the selector of the instruction's segment register (sreg field)
FLAGS  the flags image
IPN    (E)IP of the next instruction
CS     the CS selector
DX     DX (port number)
DISP   the displacement field (direct far JMP / CALL: the offset)
FIX    the GPR numbered by the uop's rfix field
BP     (E)BP
OPSZ   the operand size in bytes (2 / 4)
T2     temporary register
T3     temporary register
T4     temporary register; T4..T9 are read through the operand pre-select only (never by the
       uop right after the writer)
ERRC   the error code of the exception being delivered
T5     temporary register (pre-select only)
T6     temporary register (pre-select only)
T7     temporary register (pre-select only)
T8     temporary register (pre-select only)
T9     temporary register (pre-select only)
SSR    the SS selector
SEGF   the selector of segment register rfix
TRS    the TR selector
GPSZ   the call gate's parameter bytes: its count * the operand size
''')
# E's port A pre-select has only these sources (tetrium_exec.sv sdec, pa)
PORT_A = ('ZERO', 'REG', 'RM', 'ACC', 'OPR', 'FIX', 'DX', 'IMM', 'MEM', 'T0', 'T1', 'T3')
# T4..T9: never read by the uop right after the one that writes them
PRE_T = ('T4', 'T5', 'T6', 'T7', 'T8', 'T9')
DST = Enum('d1 / d2', '''
NONE   no register written
REG    the register of modrm.reg
RM     the register of modrm.r/m
ACC    the accumulator
OPR    the register of opcode[2:0]
T0     temporary register
T1     temporary register
SEG    the instruction's segment register (sreg field)
FIX    the GPR numbered by the uop's rfix field
T2     temporary register
T3     temporary register
T4     temporary register
T5     temporary register
T6     temporary register
T7     temporary register
T8     temporary register
T9     temporary register
SSR    SS (segment register load whatever the instruction's sreg field)
SEGF   segment register rfix
''')
ESZ = Enum('sz', '''
W0     byte if opcode bit 0 is clear, else the operand size
W3     byte if opcode bit 3 is clear, else the operand size
B      byte
Z      the operand size (16 / 32)
W16    16 bit
D32    32 bit
SS     the stack address size
SEL    a selector pushed in an operand-size slot (16-bit store, operand-size step)
TSZ    32 bit for a 386 TSS, else 16 bit
''')
WR = Enum('wr', '''
NONE   no store
PRI    store R to the primary address (a)
SEC    store R to the secondary address (sec)
''')
# descriptor check kinds (DLO / DHI / LDCS / LARV): see tetrium_exec.sv
CK = Enum('ck', '''
NONE   no descriptor check
SEG    MOV / POP / LxS to a data segment register (SS: stack segment rules)
CSJ    far JMP target
CSC    far CALL target
CSR    far RET target
LDT    LLDT
TSS    LTR
CSI    IRET target
INTG   IDT gate (DHI micro-jumps to the frame sequence)
INTCS  the IDT gate's code segment
ACC    DHI only sets the accessed bit (descriptor high dword in B)
CGJ    a call gate's code segment, JMP
CGC    a call gate's code segment, CALL (to a more privileged non-conforming segment: micro-jumps
       to the stack switch)
NSS    the inner stack from the TSS (#TS)
RSS    the outer stack of RET / IRET (#GP)
CGI    LDCS of an inner-level CALL (CPL = the segment's DPL)
INTI   LDCS of an inner-level interrupt (CPL = the segment's DPL)
LAR    LAR (LARV)
LSL    LSL (LARV)
VERR   VERR (LARV)
VERW   VERW (LARV)
V86    the segment register load of the uop is V86 style (base = selector << 4)
TTSS   the target TSS of a task switch (available; busy for IRET)
TBSY   set its busy bit (DHI store; skipped for IRET / CALL, INT)
TFRE   clear its busy bit (DHI store)
TLDT   the new task's LDT (#TS)
TCS    the new task's CS (#TS)
TSSS   the new task's SS (#TS)
TDS    the new task's data segments (#TS)
SELO   load only the selector (task switch)
''')
# (DHI reads the low dword from T5 instead of T1 for NSS, RSS, TSSS, TDS)
CHK = Enum('chk', '''
NONE     no static check
CPL0     #GP(0) unless CPL 0 (protected mode) / always in V86
IOPL     #GP(0) if CPL > IOPL (protected mode; V86: IOPL < 3): CLI, STI
V86IOPL  #GP(0) in V86 with IOPL < 3: PUSHF, POPF, INT n, IRET
''')

# ------------------------------------------------------------------ ROM word layout
FIELDS = [  # name, width   (LSB first)
    ('na_amode', 5), ('na_sec', 2), ('na_repchk', 1), ('na_abr', 3), ('na_islast', 1), ('na_endnr', 1), ('na_asz', 2), ('na_aoff', 7), ('na_ifec', 1),
    ('next', 11), ('last', 1), ('endnr', 1),
    ('mrd', 1),
    ('eop', 7), ('sa', 5), ('sb', 5), ('d1', 5), ('d2', 5), ('esz', 4),
    ('wr', 2), ('repz', 1), ('rfix', 3), ('m16', 1), ('lp', 1),
    ('ck', 5), ('chk', 2), ('sv', 1),
]
LAYOUT = {}
WORD_USED = 0
for _n, _w in FIELDS:
    LAYOUT[_n] = (WORD_USED, _w)
    WORD_USED += _w
assert WORD_USED <= UW_BITS, WORD_USED

# A-stage fields of a uop (the decoder's tables for first uops, the na_* look-ahead copy in
# the predecessor's word for the others)
AF_FIELDS = [('amode', 5), ('sec', 2), ('repchk', 1), ('abr', 3), ('islast', 1), ('endnr', 1), ('asz', 2),
             ('aoff', 7), ('ifec', 1)]
AF_BITS = sum(w for _, w in AF_FIELDS)
_p = 0
for (_n, _w), (_fn, _fw) in zip(AF_FIELDS, FIELDS):
    assert _fn == 'na_' + _n and _fw == _w and LAYOUT[_fn][0] == _p, ('na_* fields must mirror AF_FIELDS at bit 0', _fn)
    _p += _w

# address modes of supervisor accesses (paging rights of CPL 0 whatever the CPL)
SUPERVISOR_AMODES = ('DSCR', 'DSCI', 'DSCT', 'IDT', 'TSS', 'TSSA', 'LIN')


class U:
    """One micro-op.

    A stage (address generation, tetrium_agu.sv)
      a       address mode (AMODE): the primary address; mrd = 1 loads the operand from it
      aoff    byte offset added by the system-table modes (DSC*, IDT, TSS, TSSA, LIN)
      sec     secondary (store) address (SEC)
      abr     branch resolved or predicted in A (ABR)
      repchk  REP prefix: the uop checks (E)CX (string instructions)
      ifec    only runs if the exception being delivered has an error code (A1 turns it into
              a no-op otherwise)
    Memory
      mrd     the uop reads memory at its primary address (the operand MEM)
      m16     the load is 16 bits whatever the operand size (selectors)
      sv      supervisor access (paging rights of CPL 0 whatever the CPL); set automatically
              for the system-table modes, explicitly for the inner stack of a privilege change
              before CS is loaded
      wr      store R to the primary / secondary address (WR)
    E stage (tetrium_exec.sv)
      e       the operation (EOP); its operands sa / sb (SRC; sa only from PORT_A), results
              R -> d1 and R2 -> d2 (DST), size sz (ESZ)
      rfix    the register number for the FIX / SEGF sources and destinations (and the
              register / table selects of SRD, SWR, CPUID, SEGNUL, SEGVAL)
      repz    REPE / REPNE condition (CMPS / SCAS)
      ck      descriptor check kind (CK)          chk   static privilege check (CHK)
    Sequencing (the assembler, ucgen.py, resolves these into the next / last fields)
      label   names the uop for goto / lp;  label='self' with endnr=1: the uop repeats itself
              (string instructions: one uop per iteration)
      goto    the successor is the uop with this label (instead of the next in the list)
      endnr   the instruction may end after this uop (REP: last uop of an iteration)
      lp      micro-loop on the decoder's count register (ENTER level, call gate parameters):
              if the count is zero the sequence continues at the uop labelled lp, else the
              count is decremented and the normal successor follows.  The exit uop sits at
              successor address + 1 (successor even) and must not use the A stage.
    """
    ENUMS = {'a': AMODE, 'sec': SEC, 'abr': ABR, 'e': EOP, 'sa': SRC, 'sb': SRC, 'd1': DST, 'd2': DST,
             'sz': ESZ, 'wr': WR, 'ck': CK, 'chk': CHK}

    def __init__(self, a='NONE', sec='NONE', repchk=0, abr='NONE', mrd=0, e='NOP',
                 sa='ZERO', sb='ZERO', d1='NONE', d2='NONE', sz='W0', wr='NONE',
                 repz=0, label=None, goto=None, endnr=0, rfix=0, m16=0, lp=None, aoff=0, ck='NONE',
                 chk='NONE', ifec=0, sv=0):
        self.a, self.sec, self.repchk, self.abr = a, sec, repchk, abr
        self.mrd, self.e, self.sa, self.sb = mrd, e, sa, sb
        self.d1, self.d2, self.sz, self.wr, self.repz = d1, d2, sz, wr, repz
        self.label, self.goto, self.endnr = label, goto, endnr
        self.rfix = rfix
        self.aoff, self.ck, self.chk, self.ifec = aoff, ck, chk, ifec
        self.sv = 1 if (sv or a in SUPERVISOR_AMODES) else 0
        self.m16 = m16
        self.lp = lp
        for f, en in self.ENUMS.items():
            en.code(getattr(self, f), f)        # (raises on an unknown name)
        if sa not in PORT_A:
            raise UcodeError(f'sa={sa!r}: not a port A source (one of {", ".join(PORT_A)})')
        # set by the program / the assembler
        self.fill = False       # filler entry (undefined opcode #UD, prefix placeholder)
        self.orgs = []          # (sequence name, position, length) of each placement
        self.addr = None
        self.nxt = None         # successor U (look-ahead) or None
        self.last = 0

    def asz(self):
        # step size of a stack / string uop (A stage): 0 W0, 1 operand size, 2 16 bit
        if self.a not in ('POP', 'POPN', 'SI', 'DI') and self.sec in ('NONE', 'DSCA'):
            return 0
        m = {'W0': 0, 'Z': 1, 'W16': 2, 'SS': 2, 'SEL': 1, 'TSZ': 1}
        if self.sz not in m:
            raise UcodeError(f'sz={self.sz!r}: a stack / string uop takes one of {", ".join(m)}')
        return m[self.sz]

    def af(self):
        """the A-stage fields, in AF_FIELDS order"""
        return (AMODE.code(self.a), SEC.code(self.sec), self.repchk,
                ABR.code(self.abr), self.last, self.endnr, self.asz(), self.aoff, self.ifec)

    def where(self):
        return ', '.join(f'{o} #{p}' for o, p, _ in self.orgs) or 'unplaced uop'


def af_val(u):
    """the A-stage fields packed as in the ROM's na_* fields / the decoder's tables"""
    v = p = 0
    for (n, w), x in zip(AF_FIELDS, u.af()):
        v |= x << p
        p += w
    return v


def word(u):
    """the ROM word of a placed uop (None: an unused address)"""
    v = 0

    def put(name, val):
        nonlocal v
        p, w = LAYOUT[name]
        if not 0 <= val < (1 << w):
            raise UcodeError(f'{u.where()}: {name} = {val} does not fit {w} bits')
        v |= val << p
    if u is None:
        u = U()
        u.last = 1
    nx = u.nxt
    if nx is not None:
        for (n, _), x in zip(AF_FIELDS, nx.af()):
            put('na_' + n, x)
        put('next', nx.addr)
    put('last', u.last)
    put('endnr', u.endnr)
    put('mrd', u.mrd)
    put('eop', EOP.code(u.e))
    put('sa', SRC.code(u.sa))
    put('sb', SRC.code(u.sb))
    put('d1', DST.code(u.d1))
    put('d2', DST.code(u.d2))
    put('esz', ESZ.code(u.sz))
    put('wr', WR.code(u.wr))
    put('repz', u.repz)
    put('rfix', u.rfix)
    put('m16', u.m16)
    put('lp', 1 if u.lp else 0)
    put('ck', CK.code(u.ck))
    put('chk', CHK.code(u.chk))
    put('sv', u.sv)
    return v
