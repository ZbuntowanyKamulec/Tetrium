// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ZbuntowanyKamulec
// Tetrium write-back stage (W): write-through store buffer + store forwarding info
// (the D-cache write itself is done by tetrium_mem from the aligned entries)
//
// A store is 1, 2 or 4 contiguous bytes at linear address w_lin.  It is split
// here into aligned 32-bit word entries {addr[31:2], byte enables, data}:
// entry 0 = the word holding the first byte, entry 1 = the next word when the
// store crosses a 32-bit boundary.  The same aligned view of the store in W
// and of the store that was in W the cycle before is what M forwards loads from.
//
// Store buffer: SB_DEPTH word entries in distributed RAM.  A single-entry
// store merges into the newest entry if it is the same word, that entry is
// not the head (which the BIU may be taking this cycle) and both are
// mergeable (cached or write-combining memory).  Strongly-uncached stores
// never merge, so devices see every write in program order with its exact
// byte enables.
module tetrium_wb #(
    parameter int SB_DEPTH = 8,
    parameter logic [63:0] CACHEABLE = 64'hFFFF_00FF_FFFF_FFFF,   // per 16 KB region below 1 MB
    parameter logic [63:0] WCOMB     = 64'h0000_FF00_0000_0000,
    // memory types above 1 MB: up to 4 ranges {base, mask} of address bits [31:12]
    // (20 bits each, range 0 in the low bits), type {wcomb, cacheable} per range
    parameter int          MT_N    = 0,
    parameter logic [79:0] MT_BASE = '0,
    parameter logic [79:0] MT_MASK = '0,
    parameter logic [7:0]  MT_TYPE = '0
) (
    input  logic        clk,
    input  logic        rst,
    // from E
    input  logic        w_v,
    input  logic [31:0] w_lin,        // address of the first byte
    input  logic [31:2] w_lin4,       // word address of the next word (w_lin + 4)
    input  logic [1:0]  w_sz,         // 0: 1 byte, 1: 2 bytes, 2: 4 bytes
    input  logic [31:0] w_data,
    input  logic        w_two,        // store needs two entries (precomputed in E)
    input  logic        w_nowr,       // the store writes nothing (decided in E: a descriptor's accessed
                                      //   bit already set, ARPL without a change): no entry, no bytes
    input  logic        w_skip0,      // CR0.NW: the first / second word hits the D-cache and is
    input  logic        w_skip1,      //   written there only (no write-through)
    output logic        hold_w,
    input  logic        ext_hold,     // hold the W store (I-cache invalidation queue)
    // aligned view of the store in W (combinational from the W registers)
    output logic [31:2] w_a0,
    output logic [31:2] w_a1,
    output logic [3:0]  w_be0,
    output logic [3:0]  w_be1,        // zero unless the store has a second word
    output logic [31:0] w_d0,
    output logic [31:0] w_d1,
    // ... and of the store that was in W in the previous cycle (registered)
    output logic        l_st_v,
    output logic [31:2] l_a0,
    output logic [31:2] l_a1,
    output logic [3:0]  l_be0,
    output logic [3:0]  l_be1,
    output logic [31:0] l_d0,
    output logic [31:0] l_d1,
    // store buffer head (to BIU)
    output logic        sb_v,
    output logic [31:2] sb_adr,
    output logic [3:0]  sb_be,
    output logic [31:0] sb_dat,
    input  logic        sb_pop,
    output logic        sb_qempty     // no queued entries (BIU adds its outstanding writes)
);
  genvar k;
`include "tetrium_mtype.svh"
  localparam int AW = $clog2(SB_DEPTH);

  // ---------------------------------------------------------------- store -> word entries
  wire        two  = w_two;
  wire [3:0]  bm   = (w_sz == 2'd0) ? 4'b0001 : (w_sz == 2'd1) ? 4'b0011 : 4'b1111;
  wire [7:0]  be8  = w_nowr ? 8'h00 : 8'({4'b0000, bm} << w_lin[1:0]);
  wire [63:0] d64  = 64'({32'h0, w_data} << {w_lin[1:0], 3'b000});
  assign w_a0  = w_lin[31:2];
  assign w_a1  = w_lin4;
  assign w_be0 = be8[3:0];
  assign w_be1 = be8[7:4];
  assign w_d0  = d64[31:0];
  assign w_d1  = d64[63:32];
  wire [1:0]  mt0  = mtype(w_a0);
  wire [1:0]  mt1  = mtype(w_a1);
  wire        mrg0 = |mt0;
  wire        mrg1 = |mt1;

  // ---------------------------------------------------------------- FIFO
  // Entries live in distributed RAM, split into two banks by entry-index parity
  // so a two-entry store (consecutive indices) writes both in one cycle.  Only
  // the head is ever read.  A merge rewrites the newest entry from its
  // flip-flop copy (t_*) combined with the new bytes, so no RAM read is needed.
  localparam int EW = 30 + 4 + 32;
  logic [AW-1:0] rp, wp;
  logic [AW:0]   cnt;
  wire [AW-1:0] tail = wp - 1'b1;
  logic [31:2] t_a;          // copy of the newest entry: address, byte enables, data, nomerge
  logic [3:0]  t_be;
  logic [31:0] t_d;
  logic        t_nm;

  // CR0.NW write hits leave out their word: no entry, or only the other word's
  wire sk1   = w_skip1 && two;
  wire nowr  = w_nowr || (w_skip0 && (!two || sk1));
  wire two_e = two && !w_skip0 && !sk1;
  wire hi_o  = two && w_skip0 && !sk1;          // only the second word
  wire [31:2] e0_a  = hi_o ? w_a1  : w_a0;
  wire [3:0]  e0_be = hi_o ? w_be1 : w_be0;
  wire [31:0] e0_d  = hi_o ? w_d1  : w_d0;
  wire merge = w_v && !nowr && !two && mrg0 && (cnt >= 2) && !t_nm && (t_a == w_a0);
  wire [1:0] need = merge ? 2'd0 : two_e ? 2'd2 : 2'd1;
  // stall from the count only (keeps the merge compare off the stall network)
  assign hold_w = w_v && ((cnt > (AW+1)'(SB_DEPTH - 2)) || ext_hold);
  wire acc = w_v && !hold_w;
  wire [1:0] npush = (acc && !nowr) ? need : 2'd0;

  // entry 0 (merged into the tail, or new at wp) and entry 1 (second word, at wp+1)
  wire [AW-1:0] s0 = merge ? tail : wp;
  wire [AW-1:0] s1 = wp + 1'b1;
  wire [3:0]  n0_be = merge ? (t_be | w_be0) : e0_be;
  logic [31:0] n0_d;
  always_comb
    for (int b = 0; b < 4; b++) n0_d[b*8 +: 8] = (w_be0[b] || !merge) ? e0_d[b*8 +: 8] : t_d[b*8 +: 8];
  wire [EW-1:0] n0 = {e0_a, n0_be, n0_d};
  wire [EW-1:0] n1 = {w_a1, w_be1, w_d1};

  logic [EW-1:0] bk_rd [2];
  generate
  for (k = 0; k < 2; k = k + 1) begin : g_bank
    wire sel0 = (s0[0] == 1'(k));
    wire we   = acc && !nowr && (sel0 || two_e);
    tetrium_lutram #(.AW(AW-1), .DW(EW), .NR(1)) u_q (
        .clk(clk), .clr(rst), .we(we),
        .waddr(sel0 ? s0[AW-1:1] : s1[AW-1:1]), .wdata(sel0 ? n0 : n1),
        .raddr(rp[AW-1:1]), .rdata(bk_rd[k]));
  end
  endgenerate
  wire [EW-1:0] head = bk_rd[rp[0]];

  assign sb_qempty = (cnt == 0);
  assign sb_v   = (cnt != 0);
  assign sb_adr = head[EW-1 -: 30];
  assign sb_be  = head[35:32];
  assign sb_dat = head[31:0];

  always_ff @(posedge clk) begin
    if (rst) begin
      rp <= '0; wp <= '0; cnt <= '0;
    end else begin
      wp  <= wp + AW'(npush);
      if (sb_pop) rp <= rp + 1'b1;
      cnt <= cnt + (AW+1)'(npush) - (sb_pop ? 1'b1 : 1'b0);
    end
    if (acc && !nowr) begin
      t_a  <= two_e ? w_a1 : e0_a;
      t_be <= two_e ? w_be1 : n0_be;
      t_d  <= two_e ? w_d1 : n0_d;
      t_nm <= (two_e || hi_o) ? !mrg1 : !mrg0;
    end
  end

`ifdef SIM
  // ---------------------------------------------------------------- checks (simulation)
  // A behavioural copy of the queue, kept by the rules in the header (push, merge into the
  // newest entry, pop at the head), checked against the RAM queue every cycle: pointers,
  // banks, the count and the flip-flop copy of the newest entry (t_*).
  // (a fixed ring, not a queue: the SoC simulation is built --savable, which cannot save queues)
  typedef struct packed { logic nm; logic [31:2] a; logic [3:0] be; logic [31:0] d; } sbe_t;
  localparam int SHN = SB_DEPTH + 4;
  sbe_t shq [SHN];
  int   sh_h, sh_n;                 // head index, entries
  function automatic int shi(input int k); return (sh_h + k) % SHN; endfunction
  always @(posedge clk) begin
    if (rst) begin sh_h = 0; sh_n = 0; end
    else begin
      if (cnt != (AW+1)'(sh_n) || cnt > (AW+1)'(SB_DEPTH))
        $fatal(1, "wb: store buffer count %0d, %0d entries queued (depth %0d)", cnt, sh_n, SB_DEPTH);
      if (sb_v && {sb_adr, sb_be, sb_dat} != {shq[shi(0)].a, shq[shi(0)].be, shq[shi(0)].d})
        $fatal(1, "wb: store buffer head %08x/%x/%08x, expected %08x/%x/%08x", {sb_adr, 2'b00}, sb_be, sb_dat,
               {shq[shi(0)].a, 2'b00}, shq[shi(0)].be, shq[shi(0)].d);
      if (cnt != 0 && {t_nm, t_a, t_be, t_d} != shq[shi(sh_n - 1)])
        $fatal(1, "wb: copy of the newest entry (t_*) differs from the entry");
      if (sb_pop) begin
        if (sh_n == 0) $fatal(1, "wb: pop from an empty store buffer");
        else begin sh_h = shi(1); sh_n = sh_n - 1; end
      end
      if (acc && !nowr) begin
        if (merge) begin
          sbe_t t;
          if (sh_n < 1 || (sh_n < 2 && !sb_pop))
            $fatal(1, "wb: merge into the head entry");
          t = shq[shi(sh_n - 1)];
          if (t.nm || t.a != w_a0 || !mrg0) $fatal(1, "wb: merge into a different word / a non-mergeable entry");
          for (int b = 0; b < 4; b++) if (w_be0[b]) t.d[b*8 +: 8] = w_d0[b*8 +: 8];
          t.be = t.be | w_be0;
          shq[shi(sh_n - 1)] = t;
        end else begin
          sbe_t n;
          n = {(hi_o ? !mrg1 : !mrg0), e0_a, e0_be, e0_d};
          shq[shi(sh_n)] = n; sh_n = sh_n + 1;
          if (two_e) begin n = {!mrg1, w_a1, w_be1, w_d1}; shq[shi(sh_n)] = n; sh_n = sh_n + 1; end
        end
        if (sh_n > SHN) $fatal(1, "wb: store buffer check ring overflow");
      end
      if (acc && !nowr && hold_w) $fatal(1, "wb: store accepted while held");
    end
  end
`endif

  // ---------------------------------------------------------------- last store (for M)
  always_ff @(posedge clk) begin
    if (rst) l_st_v <= 1'b0;
    else     l_st_v <= w_v;
    l_a0 <= w_a0; l_a1 <= w_a1;
    l_be0 <= w_be0; l_be1 <= w_be1;
    l_d0 <= w_d0; l_d1 <= w_d1;
  end
endmodule
