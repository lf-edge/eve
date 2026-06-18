#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# analyze-floor.py — turn a sweep-floor.sh result directory into a shrink safety
# margin. The margin must cover the ext4 overhead (floor - used) for ALL cells,
# including the fragmentation/feature profiles the online check cannot observe,
# so it takes the worst case (upper envelope) per /persist size and fits a
#
#     margin(size) = A + B * size            (A = fixed reserve, B = % of size)
#
# line to it. Those two numbers feed storage-resizer's check.
#
#   ./analyze-floor.py floor-results/
import glob
import json
import os
import sys

GiB = 1 << 30
MiB = 1 << 20


def load(d):
    cells = []
    for f in sorted(glob.glob(os.path.join(d, "*.json"))):
        try:
            with open(f) as fh:
                c = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue  # empty/failed cell
        if "floorBytes" not in c or "usedBytes" not in c:
            continue
        c["_overhead"] = c["floorBytes"] - c["usedBytes"]
        # -P minus the achieved -M floor: >=0 means resize2fs's estimate is
        # conservative (safe to target online); <0 means -P under-estimates and
        # a shrink aimed at -P would fail.
        c["_pgap"] = c.get("pEstimateBytes", 0) - c["floorBytes"]
        c["_file"] = os.path.basename(f)
        cells.append(c)
    return cells


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "floor-results"
    cells = load(d)
    if not cells:
        sys.exit(f"no parseable floor results in {d}/ (run sweep-floor.sh first)")

    by_size = {}
    print(f"{'cell':<34} {'size':>6} {'fill%':>5} {'used':>9} {'floor':>9} "
          f"{'overhead':>9} {'%size':>7} {'inodeTbl':>9} {'-P−floor':>9}")
    for c in sorted(cells, key=lambda x: (x["persistSizeBytes"], x["fillPercentOfCapacity"])):
        sz, ov = c["persistSizeBytes"], c["_overhead"]
        by_size.setdefault(sz, []).append(c)
        it = c.get("inodeTableBytes", 0)
        print(f"{c['_file']:<34} {sz/GiB:>5.0f}G {c['fillPercentOfCapacity']:>5} "
              f"{c['usedBytes']/GiB:>7.2f}G {c['floorBytes']/GiB:>7.2f}G "
              f"{ov/MiB:>7.0f}M {ov*100/sz:>6.2f}% {it/MiB:>7.0f}M {c['_pgap']/MiB:>7.0f}M")

    # Is the overhead explained by the fixed inode table? If so the floor is
    # inode-driven and the proportional term B is set by mkfs's bytes-per-inode.
    with_it = [c for c in cells if c.get("inodeTableBytes", 0) > 0]
    if with_it:
        ratios = [c["_overhead"] / c["inodeTableBytes"] for c in with_it]
        print(f"\noverhead / inode-table ratio: min {min(ratios):.2f}  max {max(ratios):.2f}  "
              f"(≈1 ⇒ floor is dominated by the fixed inode table)")

    # Is resize2fs -P a safe online predictor? Safe iff it never under-estimates
    # the achieved floor (i.e. -P − floor >= 0 for every cell).
    have_p = [c for c in cells if c.get("pEstimateBytes", 0) > 0]
    if have_p:
        worst = min(have_p, key=lambda c: c["_pgap"])
        g = worst["_pgap"]
        print("\nresize2fs -P as an online predictor:")
        if g >= 0:
            print(f"  SAFE — -P never under-estimates the floor (worst margin "
                  f"{g/MiB:.0f} MiB, {worst['_file']}). The online check can target -P directly.")
        else:
            print(f"  UNSAFE alone — -P under-estimates the floor by up to "
                  f"{-g/MiB:.0f} MiB ({worst['_file']}). Add a reserve on top of -P, "
                  f"or use the used-based margin model below.")

    # Upper envelope: worst (max) overhead at each size, across fill/frag/feature.
    pts = sorted((sz, max(c["_overhead"] for c in v), max(v, key=lambda c: c["_overhead"]))
                 for sz, v in by_size.items())
    print("\nUPPER ENVELOPE (max overhead per size — the case the margin must cover):")
    for sz, mx, worst in pts:
        print(f"  {sz/GiB:>4.0f}G  max overhead {mx/MiB:>7.0f} MiB  "
              f"({mx*100/sz:>5.2f}% of size)  worst: {worst['_file']}")

    # Least-squares fit maxOverhead ~= A + B*size over the envelope points.
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    n = len(xs)
    if n >= 2 and n * sum(x * x for x in xs) != sum(xs) ** 2:
        B = (n * sum(x * y for x, y in zip(xs, ys)) - sum(xs) * sum(ys)) / \
            (n * sum(x * x for x in xs) - sum(xs) ** 2)
        A = (sum(ys) - B * sum(xs)) / n
    else:
        B, A = 0.0, max(ys)
    A = max(A, 0.0)
    print(f"\nFIT  overhead ~= {A/MiB:.0f} MiB + {B*100:.3f}% of size")
    SAFETY = 1.25
    print(f"SUGGESTED MARGIN (x{SAFETY} safety on the fit):")
    print(f"  margin = {A*SAFETY/MiB:.0f} MiB + {B*SAFETY*100:.3f}% * currentSize")
    print("\nFeed into storage-resizer check, combined with the 90% rule:")
    print("  require  target >= used + margin   AND   used <= 0.90 * target")
    print("  (target = currentSize - need; the binding bound is the larger of the two)")


if __name__ == "__main__":
    main()
