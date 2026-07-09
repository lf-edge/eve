# Partition Resizer

This is a tool to resize GPT disk partitions and their filesystems. It can grow multiple partitions,
primarily by copying the partitions to new, larger partitions in available free space on the disk.

If insufficient free space is available, and you give it an optional shrink partition that is ext4,
it will shrink the ext4 filesystem and its partition to find space, if it can.

It assumes the following:

* The disk image uses GPT partitioning.
* Any space to be recovered is from an ext4 filesystem on a partition.
* The ext4 filesystem is not mounted when resizing.
* The partitions have a specific naming/labeling scheme.

It does **not** require resizing of the ext4 partition, if there is sufficient
available space on the disk to create newer, larger partitions.

## Filesystems

It has the following handling for filesystems:

* Growing FAT32: create a new FAT32 filesystem on the new partition, copy contents.
* Growing squashfs: copy partition contents using `dd`.
* Shrinking ext4: use `resize2fs` to shrink the filesystem, then shrink the partition.

## Dependencies

resizer shells out to the standard filesystem tools:

* `resize2fs` and `e2fsck` for ext4 (shrinking and ext4 integrity checks) — the `e2fsprogs-extras` package on Linux, brew formula `e2fsprogs` on macOS.
* `fsck.fat` for FAT32 integrity checks — the `dosfstools` package on Linux, brew formula `dosfstools` on macOS.

You only need the tools for the filesystem types you actually touch: an ext4 source (shrink or grow) needs `e2fsprogs`, and a FAT32 grow source needs `dosfstools`. If a resize involves neither, no external tool is required.

## Block devices

resizer works with both disk image files and block devices. When working with block devices,
if it needs to resize an ext4 filesystem, it will copy the partition to a temporary file,
shrink the temporary file's filesystem, then copy it back to the block device, and then shrink that
partition.

## Examples

Shrink partition named sda3 (ext4) to make space, grow partition named sda1 to 20G, grow partition labeled "Data" to 100G on /dev/sda:

```sh
resizer resize --shrink-partition name:sda3 --grow-partition name:sda1:20G --grow-partition label:Data:100G /dev/sda
```

Grow partition named sda2 to 50G on disk image file disk.img:

```sh
resizer resize --grow-partition name:sda2:50G disk.img
```

### Creating a partition with `apply`

`apply` reconciles a disk to a set of desired partitions, each matched by GUID.
An existing partition is grown to at least its `minsize` (never shrunk); a GUID
not present on the disk is **created** at `minsize` with an empty filesystem. A
single `apply` can grow, create, and shrink in one pass — `--shrink` names the
only partition that may be reduced, to free space for the grows and creates.

Grow IMGA, create a new 2G FAT32 "EFI System" partition (a second ESP) at
partition number 7, and shrink "Data" to 100G to make room — all on /dev/sda:

```sh
resizer apply \
  --partition "guid=AD6871EE-31F9-4CF3-9E09-6F7A25C30051,minsize=200M,label=IMGA,type=0FC63DAF-8483-4772-8E79-3D69D8477DE4" \
  --partition "guid=AD6871EE-31F9-4CF3-9E09-6F7A25C30056,minsize=2G,label=EFI System,type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B,index=7,fs=fat32" \
  --shrink label:Data:100G \
  /dev/sda
```

The second `--partition` names a GUID not yet on the disk, so it is created:
`index=7` places it at partition slot 7, `fs=fat32` lays down an empty FAT32
filesystem. Partitions not listed are left untouched; `--shrink` is optional and
is the only operation that ever reduces a partition.

## Options

### resize

```
resizer resize [flags] <disk>
```

`<disk>` is the disk image file or block device to operate on.

| Flag | Description |
| --- | --- |
| `--grow-partition identifier:partition:size` | Partition to grow and its target size, in `identifier:partition:size` form (e.g. `name:sda1:20G`, `label:Data:100M`). Repeatable; at least one is required. |
| `--shrink-partition identifier:partition` | Optional ext4 partition to shrink to make space, used only if there is not enough free space for the grows. |
| `--fix-errors` | Repair filesystem errors found while checking the source filesystems (ext4 via `e2fsck -y`, FAT32 via `fsck.fat -a`) instead of aborting on an inconsistent source. Default is a read-only check that aborts on any inconsistency. |
| `--dry-run` | Plan the resize and log it, but make no changes. |
| `--preserve-numbers` | Renumber a relocated (grown) partition back to its original partition number, so consumers that reference it by number (e.g. `/dev/sda2`) still find it. |

Partitions are identified by `name` (e.g. `name:sda1`) or `label` (e.g.
`label:EFI System`). Sizes accept `B`, `K`, `M`, `G`, or `T` suffixes.

### apply

```
resizer apply [flags] <disk>
```

Reconciles `<disk>` to a desired set of partitions, growing or creating as needed.

| Flag | Description |
| --- | --- |
| `--partition guid=…,minsize=…[,label=…,type=…,index=…,fs=fat32\|ext4\|none]` | A desired partition. `guid=` and `minsize=` are required. If the GUID already exists it is grown to at least `minsize`; if not, it is created at `minsize` with filesystem `fs=` (default `none`). `index=` requests a specific partition number for a create. Repeatable. |
| `--shrink identifier:value:size` | Optional single partition to shrink to make room (e.g. `label:Data:100G` or `uuid:<GUID>:78G`). The only operation that reduces a partition. |
| `--fix-errors` | Repair source filesystem errors instead of aborting. |
| `--dry-run` | Plan the reconcile and log it, but make no changes. |

## Library use

resizer is also importable as a Go package. The entry point is `Run`, which
performs the same operation as the CLI:

```go
import (
	"log"

	resizer "github.com/diskfs/partitionresizer"
)

func main() {
	// optional ext4 partition to shrink for space; pass nil to disable shrinking
	shrink := resizer.NewPartitionIdentifier(resizer.IdentifierByName, "sda3")

	// partitions to grow, with their target sizes (in bytes)
	grows := []resizer.PartitionChange{
		resizer.NewPartitionChange(resizer.IdentifierByName, "sda1", 20*resizer.GB),
		resizer.NewPartitionChange(resizer.IdentifierByLabel, "Data", 100*resizer.GB),
	}

	// Run(disk, shrink, grows, fixErrors, dryRun, preserveNumbers)
	//   disk            -- image file path or block device
	//   fixErrors       -- repair filesystem errors (e2fsck -y / fsck.fat -a) instead of read-only checks
	//   dryRun          -- plan only, make no changes
	//   preserveNumbers -- renumber a relocated partition back to its original number
	if err := resizer.Run("/dev/sda", &shrink, grows, false, false, true); err != nil {
		log.Fatalf("resize failed: %v", err)
	}
}
```

Partitions are selected with `IdentifierByName`, `IdentifierByLabel`, or
`IdentifierByUUID`. Sizes passed to `NewPartitionChange` are in bytes; the
exported `KB`, `MB`, and `GB` constants are convenient multipliers.

### Errors

`Run` returns a non-nil `error` for any failure. The error wraps the failing
tool's exit status and, for the filesystem tools, includes the tail of their
stderr, so a caller gets the reason — not just `exit status N`. Tool output is
also streamed live to the process's stdout/stderr.

### Pre-flight integrity checks

Before making any change, `Run` integrity-checks every source filesystem it will
read or modify — the shrink partition and each grow source. ext4 sources are
checked with `e2fsck` and FAT32 sources with `fsck.fat`. By default the checks
are read-only and an inconsistent filesystem aborts the resize; pass `fixErrors`
to repair instead. squashfs sources are copied raw and have no applicable check,
so a corrupt squashfs source is reproduced faithfully.

## Testing

The suite has three tiers, selected with `-short` and a few environment
variables:

| Invocation | What runs |
|---|---|
| `go test ./...` | All tests, including end-to-end shrinks/copies of multi-GB fixtures (slow). |
| `go test -short ./...` | Skips those slow end-to-end fixtures; everything else still runs. |
| `RESIZER_CHAOS=1 go test -run '^TestChaosKill$' .` | Adds the SIGKILL resume soak (see below). |

The chaos soak is gated separately from `-short` because it is an open-ended
stress run, not a pass/fail CI gate, so it stays off even in a full `go test
./...`. Its environment knobs:

| Variable | Effect |
|---|---|
| `RESIZER_CHAOS=1` | Enable the chaos soak. Without it (and without `CHAOS_GPT_DELAY`) the test skips. |
| `CHAOS_SEED=<n>` | Seed the kill-timing RNG for a reproducible run. Default: random, logged as `CHAOS_SEED=<n>`. |
| `CHAOS_GPT_DELAY=<dur>` | Enable the soak *and* build the resizer subprocess with `-tags chaos`, delaying around GPT-sector writes so kills can land inside the otherwise-instantaneous `updatePartitions`/`createPartitions` table writes (e.g. `5s`). |
| `CHAOS_COPY_STATE=1` | After each kill, also classify the grow target's copied data as empty/partial/complete. |

`-tags chaos` is not something you pass to `go test`: the chaos test builds the
resizer subprocess with it internally when `CHAOS_GPT_DELAY` is set.

### Chaos / resume soak test

`TestChaosKill` is a stress test, not a CI gate. It repeatedly runs the full
two-step resize (shrink the data partition, then grow the image/ESP partitions into the freed space) as a subprocess,
SIGKILLs it at random points across the pipeline, then re-runs to completion and
asserts the result always matches an uninterrupted resize. Because it is slow and
meant to run for minutes-to-hours, `go test ./...` skips it by default; enable it
explicitly:

```sh
# basic chaos run (kills land wherever timing puts them)
RESIZER_CHAOS=1 go test -run '^TestChaosKill$' -timeout 30m .

# reproduce a specific run
RESIZER_CHAOS=1 CHAOS_SEED=12345 go test -run '^TestChaosKill$' -timeout 30m .

# widen the window around GPT-table writes so kills can land inside the
# updatePartitions/createPartitions writes (builds the resizer with -tags chaos)
CHAOS_GPT_DELAY=5s go test -run '^TestChaosKill$' -timeout 40m .
```

Longer soaks are driven by an outer loop that re-invokes the test. It needs
`mksquashfs` (squashfs-tools) in addition to `resize2fs`/`e2fsck`. After each
kill the test logs the pipeline step it interrupted and the on-disk GPT integrity
(primary/backup header and entry-array CRCs, and primary↔backup entry equality);
set `CHAOS_COPY_STATE=1` to also classify the grow target's data copy as
empty/partial/complete.

