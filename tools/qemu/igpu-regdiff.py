#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Decode and diff Intel iGPU MMIO register blobs captured by igpu-dump.py.

Runs LOCALLY on the workstation (never on the node): scp the .bin blobs off the
node, then diff. Typical use compares a "corrupted" state (A) against a
"recovered" state (B), each captured twice so volatile registers (scanline,
frame counters, timestamps) can be filtered out automatically:

    igpu-regdiff.py --a A1.bin A2.bin --b B1.bin B2.bin

A register is reported only if it is *stable within* each state and *differs
between* states -- those are the prime suspects for the corruption.

A single blob per state also works (raw diff, no volatility filter):

    igpu-regdiff.py --a A.bin --b B.bin

Blob byte offset i maps to BAR0 register offset range_start + i. range_start is
read from the blob's sidecar .json (written by igpu-dump.py), or override with
--start.
"""
# Terse standalone diagnostic script: relax pylint style checks that
# don't add value here.
# pylint: disable=invalid-name,consider-using-f-string,missing-module-docstring,missing-class-docstring,missing-function-docstring,consider-using-with,unspecified-encoding,broad-exception-caught,multiple-imports,multiple-statements,too-many-locals,too-many-statements,unnecessary-lambda-assignment
import argparse, json, os, struct, sys

# --- Curated Gen12 (TGL/ADL/RPL) display register map, by absolute BAR offset.
# Not exhaustive; unknown offsets are still reported, just without a name.
def _build_regmap():
    m = {}
    # Power wells / DBUF / CDCLK / DC states
    m[0x44fe8] = "DBUF_CTL_S2"
    m[0x45008] = "DBUF_CTL_S1"
    m[0x45400] = "PWR_WELL_CTL1_BIOS"
    m[0x45404] = "PWR_WELL_CTL2_DRIVER"
    m[0x45408] = "PWR_WELL_CTL3_KVMR"
    m[0x4540c] = "PWR_WELL_CTL4_DEBUG"
    m[0x45440] = "PWR_WELL_CTL_AUX1"
    m[0x45444] = "PWR_WELL_CTL_AUX2"
    m[0x45480] = "PWR_WELL_CTL_DDI1"
    m[0x45484] = "PWR_WELL_CTL_DDI2"
    m[0x45504] = "DC_STATE_EN"
    m[0x46000] = "CDCLK_CTL"
    m[0x46070] = "CDCLK_PLL_ENABLE"
    m[0x46140] = "TRANS_CLK_SEL_A"
    m[0x46144] = "TRANS_CLK_SEL_B"
    # FBC
    m[0x43208] = "FBC_CONTROL"
    # Per-transcoder timing generator + DDI func ctl (A=0,B=1,C=2,D=3)
    tnames = {0: "A", 1: "B", 2: "C", 3: "D"}
    for t, nm in tnames.items():
        b = 0x60000 + t * 0x1000
        m[b + 0x00] = "TRANS_HTOTAL_%s" % nm
        m[b + 0x04] = "TRANS_HBLANK_%s" % nm
        m[b + 0x08] = "TRANS_HSYNC_%s" % nm
        m[b + 0x0c] = "TRANS_VTOTAL_%s" % nm
        m[b + 0x10] = "TRANS_VBLANK_%s" % nm
        m[b + 0x14] = "TRANS_VSYNC_%s" % nm
        m[b + 0x1c] = "PIPE_SRCSZ_%s" % nm
        m[b + 0x28] = "TRANS_VSYNCSHIFT_%s" % nm
        m[b + 0x30] = "TRANS_MULT_%s" % nm
        m[b + 0x400] = "TRANS_DDI_FUNC_CTL_%s" % nm
        m[b + 0x404] = "TRANS_DDI_FUNC_CTL2_%s" % nm
        m[b + 0x410] = "TRANS_MSA_MISC_%s" % nm
    # DDI buffer control (per DDI port a..e / TC)
    for p in range(6):
        m[0x64000 + p * 0x100] = "DDI_BUF_CTL_%d" % p
        m[0x64040 + p * 0x100] = "DP_TP_CTL_%d" % p
        m[0x64044 + p * 0x100] = "DP_TP_STATUS_%d" % p
    # Per-pipe: pipe/cursor/plane/scaler (A=0,B=1,C=2,D=3)
    for p, nm in tnames.items():
        b = 0x70000 + p * 0x1000
        m[b + 0x000] = "PIPE_DSL_%s" % nm            # scanline (volatile)
        m[b + 0x008] = "TRANSCONF_%s" % nm           # enable=bit31 state=bit30
        m[b + 0x024] = "PIPESTAT_%s" % nm            # status (partly volatile)
        m[b + 0x028] = "PIPE_FRMTMSTMP_%s" % nm      # (volatile)
        m[b + 0x030] = "PIPE_MISC_%s" % nm
        m[b + 0x040] = "PIPE_FRMCNT_%s" % nm         # (volatile)
        m[b + 0x044] = "PIPE_FLIPCNT_%s" % nm        # (volatile)
        m[b + 0x080] = "CUR_CTL_%s" % nm
        m[b + 0x084] = "CUR_BASE_%s" % nm
        m[b + 0x088] = "CUR_POS_%s" % nm
        # Universal plane 1 (primary)
        m[b + 0x180] = "PLANE_CTL_1_%s" % nm         # enable=bit31, pixfmt, tiling
        m[b + 0x188] = "PLANE_STRIDE_1_%s" % nm
        m[b + 0x18c] = "PLANE_POS_1_%s" % nm
        m[b + 0x190] = "PLANE_SIZE_1_%s" % nm
        m[b + 0x19c] = "PLANE_SURF_1_%s" % nm        # surface base (arm)
        m[b + 0x1a4] = "PLANE_OFFSET_1_%s" % nm
        m[b + 0x1ac] = "PLANE_AUX_OFFSET_1_%s" % nm
        m[b + 0x1cc] = "PLANE_COLOR_CTL_1_%s" % nm
        m[b + 0x27c] = "PLANE_BUF_CFG_1_%s" % nm     # DBUF allocation
        for lvl in range(8):
            m[b + 0x240 + lvl * 4] = "PLANE_WM_1_%s_L%d" % (nm, lvl)
        m[b + 0x268] = "PLANE_WM_TRANS_1_%s" % nm
    # Pipe scalers (2 per pipe)
    for p, nm in tnames.items():
        sb = 0x68000 + p * 0x800
        m[sb + 0x170] = "PS_WIN_POS_1_%s" % nm
        m[sb + 0x174] = "PS_WIN_SZ_1_%s" % nm
        m[sb + 0x180] = "PS_CTRL_1_%s" % nm
    return m

REGMAP = _build_regmap()

def load(path):
    data = open(path, "rb").read()
    start = None
    side = path + ".json"
    if os.path.exists(side):
        start = json.load(open(side)).get("range_start")
    return data, start

def as_dwords(data):
    n = len(data) // 4
    return struct.unpack_from("<%dI" % n, data, 0)

def name(off):
    return REGMAP.get(off, "")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--a", nargs="+", required=True, help="state A blob(s)")
    ap.add_argument("--b", nargs="+", required=True, help="state B blob(s)")
    ap.add_argument("--start", type=lambda x: int(x, 0), default=None,
                    help="BAR offset of blob byte 0 (else read from .json)")
    ap.add_argument("--show-volatile", action="store_true",
                    help="also list registers filtered out as volatile")
    args = ap.parse_args()

    a_blobs = [load(p) for p in args.a]
    b_blobs = [load(p) for p in args.b]
    start = args.start
    if start is None:
        for _, s in a_blobs + b_blobs:
            if s is not None:
                start = s; break
    if start is None:
        sys.exit("range_start unknown: pass --start or provide .json sidecars")

    a = [as_dwords(d) for d, _ in a_blobs]
    b = [as_dwords(d) for d, _ in b_blobs]
    n = min(len(x) for x in a + b)

    volatile, changed = [], []
    for i in range(n):
        av = [x[i] for x in a]
        bv = [x[i] for x in b]
        a_stable = len(set(av)) == 1
        b_stable = len(set(bv)) == 1
        if not (a_stable and b_stable):
            if av[0] != bv[0] or not a_stable or not b_stable:
                volatile.append(i)
            continue
        if av[0] != bv[0]:
            changed.append(i)

    off = lambda i: start + i * 4
    print("# range 0x%x..0x%x  dwords=%d  A=%d blob(s)  B=%d blob(s)"
          % (start, start + n * 4, n, len(a), len(b)))
    print("# stable-diff registers (A != B, stable within each state): %d" % len(changed))
    print("%-9s %-24s %-10s %-10s %s" % ("OFFSET", "NAME", "A", "B", "A^B"))
    for i in changed:
        print("0x%06x %-24s 0x%08x 0x%08x 0x%08x"
              % (off(i), name(off(i)) or "?", a[0][i], b[0][i], a[0][i] ^ b[0][i]))
    if args.show_volatile:
        print("\n# volatile (filtered): %d" % len(volatile))
        for i in volatile:
            print("0x%06x %-24s A~%08x B~%08x"
                  % (off(i), name(off(i)) or "?", a[0][i], b[0][i]))

if __name__ == "__main__":
    main()
