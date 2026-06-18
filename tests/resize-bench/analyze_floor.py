#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Turn a sweep-floor.sh result directory into a shrink safety margin.

The margin must cover the ext4 overhead (floor - used) for ALL cells,
including the fragmentation/feature profiles the online check cannot observe,
so it takes the worst case (upper envelope) per /persist size and fits a

    margin(size) = A + B * size            (A = fixed reserve, B = % of size)

line to it. Those two numbers feed storage-resizer's check.

    ./analyze_floor.py floor-results/
"""
import glob
import json
import os
import sys

GIB = 1 << 30
MIB = 1 << 20
SAFETY = 1.25


def load(result_dir):
    """Return the parseable floor-result cells in result_dir."""
    cells = []
    for path in sorted(glob.glob(os.path.join(result_dir, "*.json"))):
        try:
            with open(path, encoding="utf-8") as handle:
                cell = json.load(handle)
        except (json.JSONDecodeError, OSError):
            continue  # empty/failed cell
        if "floorBytes" not in cell or "usedBytes" not in cell:
            continue
        cell["_overhead"] = cell["floorBytes"] - cell["usedBytes"]
        # -P minus the achieved -M floor: >=0 means resize2fs's estimate is
        # conservative (safe to target online); <0 means -P under-estimates and
        # a shrink aimed at -P would fail.
        cell["_pgap"] = cell.get("pEstimateBytes", 0) - cell["floorBytes"]
        cell["_file"] = os.path.basename(path)
        cells.append(cell)
    return cells


def print_cells(cells):
    """Print one row per cell; return the cells grouped by /persist size."""
    by_size = {}
    print(f"{'cell':<34} {'size':>6} {'fill%':>5} {'used':>9} {'floor':>9} "
          f"{'overhead':>9} {'%size':>7} {'inodeTbl':>9} {'-P−floor':>9}")
    for cell in sorted(cells, key=lambda x: (x["persistSizeBytes"],
                                             x["fillPercentOfCapacity"])):
        size, overhead = cell["persistSizeBytes"], cell["_overhead"]
        by_size.setdefault(size, []).append(cell)
        inode_tbl = cell.get("inodeTableBytes", 0)
        print(f"{cell['_file']:<34} {size/GIB:>5.0f}G {cell['fillPercentOfCapacity']:>5} "
              f"{cell['usedBytes']/GIB:>7.2f}G {cell['floorBytes']/GIB:>7.2f}G "
              f"{overhead/MIB:>7.0f}M {overhead*100/size:>6.2f}% "
              f"{inode_tbl/MIB:>7.0f}M {cell['_pgap']/MIB:>7.0f}M")
    return by_size


def print_predictors(cells):
    """Report whether the inode table and resize2fs -P explain the floor."""
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
        gap = worst["_pgap"]
        print("\nresize2fs -P as an online predictor:")
        if gap >= 0:
            print(f"  SAFE — -P never under-estimates the floor (worst margin "
                  f"{gap/MIB:.0f} MiB, {worst['_file']}). The online check can target -P directly.")
        else:
            print(f"  UNSAFE alone — -P under-estimates the floor by up to "
                  f"{-gap/MIB:.0f} MiB ({worst['_file']}). Add a reserve on top of -P, "
                  f"or use the used-based margin model below.")


def fit_line(sizes, peaks):
    """Least-squares fit y ~= fixed + slope*x; return (fixed, slope), fixed >= 0."""
    count = len(sizes)
    denom = count * sum(x * x for x in sizes) - sum(sizes) ** 2
    if count >= 2 and denom != 0:
        slope = (count * sum(x * y for x, y in zip(sizes, peaks)) - sum(sizes) * sum(peaks)) / denom
        fixed = (sum(peaks) - slope * sum(sizes)) / count
    else:
        slope, fixed = 0.0, max(peaks)
    return max(fixed, 0.0), slope


def main():
    """Print the per-cell table, the predictor verdicts and the suggested margin."""
    result_dir = sys.argv[1] if len(sys.argv) > 1 else "floor-results"
    cells = load(result_dir)
    if not cells:
        sys.exit(f"no parseable floor results in {result_dir}/ (run sweep-floor.sh first)")

    by_size = print_cells(cells)
    print_predictors(cells)

    # Upper envelope: worst (max) overhead at each size, across fill/frag/feature.
    envelope = sorted((size, max(group, key=lambda c: c["_overhead"]))
                      for size, group in by_size.items())
    print("\nUPPER ENVELOPE (max overhead per size — the case the margin must cover):")
    for size, worst in envelope:
        peak = worst["_overhead"]
        print(f"  {size/GIB:>4.0f}G  max overhead {peak/MIB:>7.0f} MiB  "
              f"({peak*100/size:>5.2f}% of size)  worst: {worst['_file']}")

    fixed, slope = fit_line([size for size, _ in envelope],
                            [worst["_overhead"] for _, worst in envelope])
    print(f"\nFIT  overhead ~= {fixed/MIB:.0f} MiB + {slope*100:.3f}% of size")
    print(f"SUGGESTED MARGIN (x{SAFETY} safety on the fit):")
    print(f"  margin = {fixed*SAFETY/MIB:.0f} MiB + {slope*SAFETY*100:.3f}% * currentSize")
    print("\nFeed into storage-resizer check, combined with the 90% rule:")
    print("  require  target >= used + margin   AND   used <= 0.90 * target")
    print("  (target = currentSize - need; the binding bound is the larger of the two)")


if __name__ == "__main__":
    main()
