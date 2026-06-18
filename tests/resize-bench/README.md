# resize-bench

Times the two phases of the EVE-kvm → EVE-k disk repartition independently, to
judge how long the device is "dark" (no EVE-OS running, no controller reporting)
versus how much work could run online:

- **SHRINK** — `e2fsck` + `resize2fs` on a filled ext4 `/persist` (P3).
- **GROW** — `mkfs.fat` ESP2 + copy ESP content (36 MB) + copy each IMGx image (300 MB).

It shells out to the same utilities the real resizer uses, so the numbers
reflect real tool + I/O cost. The GPT partition-table writes themselves are
sub-second and excluded. Required tools and the Alpine packages that provide
them:

| tool | Alpine package |
|------|----------------|
| `mkfs.ext4`, `e2fsck` | `e2fsprogs` |
| `resize2fs` | `e2fsprogs-extra` (**not** the base `e2fsprogs`) |
| `mkfs.fat` / `mkfs.vfat` | `dosfstools` |
| `mcopy` | `mtools` |

```sh
apk add e2fsprogs e2fsprogs-extra dosfstools mtools
```

The tool checks for these at startup and, if any are missing, prints exactly
which `apk add` to run.

## Important: measure on real storage

All scratch I/O happens under `--workdir`. **It must sit on the medium you want
to measure** (the device's eMMC/SSD). The tool detects a tmpfs/ramfs workdir via
`statfs` and refuses — measuring RAM would be meaningless. It also prints the
detected filesystem type in its first status line (e.g. `workdir … (ext2/3/4)`)
so you can verify the medium — it does not prompt; there is no interactive
confirmation.

### Disk usage and how to measure it

`--workdir` is usually a plain directory on an existing filesystem (e.g.
`/var/scratch` on `/`), not a dedicated mount, so `df <workdir>` reports the
*whole* underlying filesystem, not the bench's share. Peak usage is the backing
image `resize-bench-scratch/persist.img`, which grows up to **`--persist-size`**
(it is created sparse and fills as blocks are touched; `mount -o loop` has no
`discard`, so deletes during fill/aging do not shrink it — it tends toward full).
Budget ~`--persist-size` of free space.

To see the bench's own usage, measure the scratch dir with **`du -x`** (or the
image directly) — a plain `du` descends into the loop mount and *double-counts*
the fill files on top of the image:

```sh
du -x -sh /var/scratch/resize-bench-scratch/*          # -x: don't cross into mnt/
du -h  /var/scratch/resize-bench-scratch/persist.img   # the image's real allocation
```

## Build

Pure Go, no cgo — `CGO_ENABLED=0` gives a fully static binary that runs on
Alpine/musl as well as glibc (no musl cross-toolchain needed):

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -o resize-bench .   # arm64 device
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o resize-bench .   # amd64
```

## Run (use sudo for in-place fill + cold caches)

```sh
sudo ./resize-bench --workdir /var/scratch --persist-size 100G --fill 60 --shrink 22G
```

`sudo` matters: with root the fill is written in place via a loop mount (no
double space) and the page cache is dropped before each timed phase, giving
cold-cache (realistic) numbers. Without root it falls back to `mkfs.ext4 -d`
(needs ~`fill` extra scratch space) and cannot drop caches (numbers are
cache-warm) — fine for a quick relative check, not for absolute figures.

## Flags

| flag | default | meaning |
|------|---------|---------|
| `--workdir` | *(required)* | scratch location — put on the medium under test |
| `--persist-size` | `64G` | ext4 P3 size to create |
| `--fill` | `40` | percent of the ext4 **usable capacity** to fill (see below) |
| `--shrink` | `22G` | amount to shrink P3 by (target = persist-size − shrink) |
| `--phase` | `both` | which phase to measure: `shrink`, `grow`, `both`, or `floor` |
| `--age` | `0` | floor mode: N delete-then-refill churn cycles to fragment the fs (needs mount) |
| `--mkfs-opts` | *(none)* | extra `mkfs.ext4` args, e.g. `-O encrypt` (EVE) or `-O ^has_journal` |
| `--small-files` | `2000` | number of small files in the fill mix |
| `--esp-size` | `2G` | ESP2 filesystem size (`mkfs.fat` target) |
| `--esp-copy` | `36M` | ESP content copied in grow |
| `--img-copy` | `300M` | each IMGx content copied |
| `--img-count` | `2` | number of IMGx copied |
| `--fill-method` | `auto` | `mount` (root, in-place) or `mke2fs` (root-free) |
| `--drop-caches` | `true` | drop page cache before each phase (needs root) |
| `--json` | `false` | machine-readable output (durations as `s`/string, not ns) |

(Flags are GNU-style `--word`; Go's `flag` also accepts a single dash.)

## `--fill` is relative to usable capacity

`--fill 75` fills 75% of the **filesystem's usable capacity**, not 75% of the
partition. ext4 reserves space the data can't use — inode tables, the journal,
group descriptors/bitmaps, the 5% root-reserved blocks, `lost+found` — so the
usable capacity is several percent below the partition size. The tool mkfs's an
empty fs first, reads the real capacity, and fills that fraction; it prints
`ext4 usable capacity X; filled Y (N% of capacity)`. This way a `--fill 75` run
results in an fs that is ~75% full (what `df` would show), and `resize2fs`'s
*minimum* (data + non-freeable overhead) stays close to the filled size.

If the shrink target is below that minimum, `resize2fs` cannot fit the data and
the tool reports *"filesystem is too full to shrink to … — lower --fill or
--shrink, or raise --persist-size"* (instead of the raw `New size smaller than
minimum`). Shrink cost is driven by how much data must be relocated below the new
boundary, so sweep `--fill` to find where shrink time starts to dominate grow.

## Fill size distribution

To resemble a real `/persist` rather than a few identical blobs, the fill is a
two-tier mix (fixed-seed PRNG, so runs are comparable):

- a bounded number of **small files** (4 KiB–1 MiB: logs, configs, certs) for
  realistic inode/extent pressure — count set by `--small-files`;
- the remaining bytes in **large files** (64–512 MiB: volume images, container
  blobs).

## Suggested sweep

Across fill levels and on each medium of interest (laptop SSD vs device eMMC):

```sh
for f in 30 50 70 85; do
  sudo ./resize-bench --workdir /var/scratch --persist-size 100G --fill $f --shrink 22G --json
done
```

## Characterizing the ext4 shrink floor (`--phase floor`)

The shrink-margin policy in `storage-resizer` (the `--max-full 90` bound) is a
placeholder, not a measured safe point. `resize2fs` refuses to shrink below a
filesystem's *minimum* size — data blocks plus non-relocatable metadata (inode
tables, group descriptors, journal) — which is **not** a fixed percentage: it
rises with fragmentation and file count, and the metadata floor has a
size-independent component. We want an **upper bound on that overhead** (`floor −
used`) so it can be used as a shrink safety margin: a shrink is likely to succeed
only if the target leaves room for it.

`--phase floor` measures the floor directly. It builds the same filled ext4 as
the shrink benchmark, then, on the **unmounted** image:

1. `e2fsck -fy` — clean the fs (a `resize2fs` precondition);
2. read `used` from the superblock (`(blockCount − freeBlocks) × blockSize`);
3. `resize2fs -P` — the tool's *estimated* minimum;
4. `resize2fs -M` — actually minimize, then re-read the superblock: that achieved
   size is the real **floor**.

It reports `used`, the `-P` estimate, the floor, and `overhead = floor − used`
(as MiB, % of used, and % of size), the **inode table** size (count × inode
size, read from the superblock — fixed at mkfs and not reclaimed by resize2fs,
so the prime suspect for the size-proportional part of the floor), and whether
the default 22 GB shrink still fits above the floor. The long fill/aging phases
print a throttled progress line so a multi-minute run doesn't go dark.

### Mounted vs unmounted, and what the online check can use

`resize2fs` supports **online** resizing only for *growing* a mounted filesystem;
the actual shrink/minimize (`-M`) requires the fs to be **unmounted**
(`man resize2fs`). The bench honors this — it releases the loop mount before the
`-M` step. The real `storage-resizer` shrink likewise runs offline, in the "dark"
window, so that constraint is already met there.

The read-only estimate **`resize2fs -P` does work on a mounted fs** (verified:
`resize2fs -P /dev/mapper/...` on a live ext4 root). So the **online** `check`
(run while `/persist` is mounted) has two options for deciding whether a shrink
will succeed:

1. call `resize2fs -P` on the mounted `/persist` for a live floor estimate
   (requires the `e2fsprogs-extra` `resize2fs` binary in the online environment);
   or
2. apply a **static margin model** — `used + A + B×size` — read straight from the
   ext4 superblock (a plain block read; no external tool), where `A`/`B` come
   from this sweep.

Whether option 1 is safe on its own depends on whether `-P` ever *under*-estimates
the true `-M` floor — if it can, a shrink targeted at `-P` would fail. The sweep
records both `-P` and the achieved `-M` floor in every cell precisely to answer
that; `analyze-floor.py` reports the `-P − floor` gap. If `-P` is always ≥ the
floor (conservative), the online check can rely on it directly; otherwise it needs
the margin model (option 2), as a resize2fs-free fallback or as a reserve added on
top of `-P`. Either way the sweep below is what produces the policy.

> Note: the floor is a property of the filesystem geometry + contents, **not** the
> storage medium, so this sweep can run on any box — unlike the *timing*
> benchmark, which needs the real eMMC. It does need root: a realistic floor
> requires the in-place mount fill (`mkfs.ext4 -d` scatters data and inode tables
> across all block groups, which makes `resize2fs` report a near-full,
> meaningless floor), and `--age` churns files on the mounted fs.

### The sweep

`sweep-floor.sh` drives the matrix from the `storage-resizer` README — varying,
independently:

- **fill level** 30 … 95%, to find where shrink starts failing;
- **`/persist` size** 8G/32G/64G/100G/256G, to separate the size-proportional
  part of the floor from any fixed component;
- **fragmentation** (`mix` two-tier / `small` inode-heavy / `aged` churn via
  `--age`), which raises the relocatable-block count and the floor;
- **ext4 feature set** (`default` / `eve` = `-O encrypt` per `storage-init.sh` /
  `nojournal`), which changes the metadata footprint.

```sh
CGO_ENABLED=0 go build -o resize-bench .
sudo ./sweep-floor.sh /var/scratch      # one JSON report per cell -> floor-results/
./analyze-floor.py floor-results        # per-cell table + margin model
```

`analyze-floor.py` computes `overhead = floor − used` per cell, takes the **upper
envelope** (worst case per size, across the fragmentation/feature profiles the
online check can't observe), and least-squares-fits

```
margin(size) = A + B × size      (A = fixed reserve in MB, B = % of size)
```

with a safety multiplier. The fit's intercept `A` *is* the size-independent
component — so the output directly answers the README's open question (single
percentage vs percentage **plus** a fixed reserve). Feed the resulting `A` and
`B` into `storage-resizer check`, combined with the operating-headroom rule:

```
require   target ≥ used + margin(size)   AND   used ≤ 0.90 × target
          (target = currentSize − need; the binding bound is the larger)
```

Record the sweep output in `~/notes/`.
