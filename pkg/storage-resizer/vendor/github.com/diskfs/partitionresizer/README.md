# Partition Resizer

This is a tool to reconcile a GPT disk to a desired set of partitions. It grows multiple
partitions (primarily by copying them to new, larger partitions in available free space),
creates partitions that are absent, and optionally shrinks one partition to free space —
all in a single, idempotent, restart-safe pass.

You declare the partitions you want; each is grown to at least its size, or created if
absent, and one named partition may be shrunk to make room. A partition already at least
its size is left untouched — nothing is ever shrunk except the designated shrink partition.

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

Grow the partition labeled `sda1` to 20G and the one labeled "Data" to 100G,
shrinking `sda3` (ext4) to make space if needed, on /dev/sda:

```sh
resizer \
  --partition match=name:sda1,minsize=20G \
  --partition match=label:Data,minsize=100G \
  --shrink name:sda3 \
  /dev/sda
```

`--shrink name:sda3` with no size is *shrink-to-fit*: sda3 is shrunk only if the
grows do not otherwise fit, and only by as much as they need. Give an explicit
size (`--shrink name:sda3:78G`) to always shrink to that size.

Grow the partition labeled sda2 to 50G on a disk image file:

```sh
resizer --partition match=label:sda2,minsize=50G disk.img
```

### Creating a partition

A `--partition` identified by `guid=` grows the partition with that GUID if it
exists, or **creates** it if absent, at `minsize` with an empty filesystem.
This example grows IMGA, creates a new 2G FAT32 "EFI System" partition (a second
ESP) at partition number 7, and shrinks "Data" to 100G to make room — all on
/dev/sda:

```sh
resizer \
  --partition "guid=AD6871EE-31F9-4CF3-9E09-6F7A25C30051,minsize=200M,label=IMGA,type=0FC63DAF-8483-4772-8E79-3D69D8477DE4,index=2" \
  --partition "guid=AD6871EE-31F9-4CF3-9E09-6F7A25C30056,minsize=2G,label=EFI System,type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B,index=7,fs=fat32" \
  --shrink label:Data:100G \
  /dev/sda
```

The second `--partition` names a GUID not yet on the disk, so it is created:
`index=7` places it at partition slot 7, `fs=fat32` lays down an empty FAT32
filesystem. Partitions not listed are left untouched; `--shrink` is optional and
is the only operation that ever reduces a partition.

## Options

```
resizer [flags] [disk]
```

`[disk]` is the disk image file or block device to operate on. It may be omitted,
in which case the disk is discovered from the `match=`/`--shrink` identifiers
(they must all resolve to the same disk).

| Flag | Description |
| --- | --- |
| `--partition <keys>` | A desired partition, as comma-separated `key=value` pairs (repeatable). `minsize=` is required. Identify an existing partition to grow with either `guid=` or `match=<identifier>` (`match=name:sda1`, `match=label:Data`, `match=uuid:<GUID>`); a `guid=` not present on the disk is **created**. Optional: `label=`, `type=` (GPT type GUID, asserted on a match), `index=` (requested partition number), `fs=fat32\|ext4\|none` (filesystem for a create; default `none`). |
| `--shrink identifier:value[:size]` | Optional single partition to shrink to make room (e.g. `label:Data:100G`, `uuid:<GUID>:78G`, or `label:Data` for shrink-to-fit). The only operation that reduces a partition. |
| `--fix-errors` | Repair filesystem errors found while checking the source filesystems (ext4 via `e2fsck -y`, FAT32 via `fsck.fat -a`) instead of aborting on an inconsistent source. Default is a read-only check that aborts on any inconsistency. |
| `--dry-run` | Plan the reconcile and log it, but make no changes. |

Partitions are identified by `name` (e.g. `name:sda1`, resolved via sysfs on a
block device), `label` (e.g. `label:EFI System`), or `uuid`. Sizes accept `B`,
`K`, `M`, `G`, or `T` suffixes. Grown partitions keep their original partition
number, so consumers that reference a partition by number (e.g. `/dev/sda2`)
still find it after a resize.

## Library use

resizer is also importable as a Go package. The entry point is `Apply`, which
performs the same operation as the CLI:

```go
import (
	"log"

	resizer "github.com/diskfs/partitionresizer"
)

func main() {
	// desired partitions: each is grown to at least MinSize, or created if the
	// GUID is absent. An existing partition to grow is located by Match
	// (name/label/uuid) or, when Match is nil, by GUID.
	desired := []resizer.PartitionSpec{
		{Match: resizer.NewPartitionIdentifier(resizer.IdentifierByName, "sda1"), MinSize: 20 * resizer.GB},
		{Match: resizer.NewPartitionIdentifier(resizer.IdentifierByLabel, "Data"), MinSize: 100 * resizer.GB},
	}

	// optional single partition to shrink for space; nil disables shrinking.
	// Size 0 == shrink-to-fit; a positive Size shrinks to exactly that size.
	shrink := &resizer.ShrinkSpec{ID: resizer.NewPartitionIdentifier(resizer.IdentifierByName, "sda3")}

	// Apply(disk, desired, shrink, fixErrors, dryRun)
	//   disk      -- image file path or block device; "" to auto-discover from the identifiers
	//   fixErrors -- repair filesystem errors (e2fsck -y / fsck.fat -a) instead of read-only checks
	//   dryRun    -- plan only, make no changes
	if err := resizer.Apply("/dev/sda", desired, shrink, false, false); err != nil {
		log.Fatalf("apply failed: %v", err)
	}
}
```

To create a partition, give a `PartitionSpec` with a `GUID` not present on the
disk (leaving `Match` nil), plus `Label`, `TypeGUID`, `Index`, and `FS`.
Identifiers use `IdentifierByName`, `IdentifierByLabel`, or `IdentifierByUUID`;
sizes are in bytes, with the exported `KB`, `MB`, and `GB` constants as
convenient multipliers. Grown partitions keep their original partition number.

### Errors

`Apply` returns a non-nil `error` for any failure. The error wraps the failing
tool's exit status and, for the filesystem tools, includes the tail of their
stderr, so a caller gets the reason — not just `exit status N`. Tool output is
also streamed live to the process's stdout/stderr.

### Pre-flight integrity checks

Before making any change, `Apply` integrity-checks every source filesystem it will
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

