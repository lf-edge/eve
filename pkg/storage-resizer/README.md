# storage-resizer

Standalone binary that performs the boot-disk repartition for the EVE-kvm ⇄
EVE-k conversion. It is kept out of pillar (so `go-diskfs`/`partitionresizer`
do not enter the pillar module) and is invoked two ways:

- from **storage-init** in early boot (offline, `/persist` unmounted) to shrink
  `/persist`, grow the partitions, and — once `/persist` is remounted — `restore`
  the backed-up files;
- from **baseosmgr** while EVE runs (via `pkg/pillar/diskconvert`, which `exec`s
  this binary) for the pre-flight `check`, the online grow, and the backup.

The filesystem/partition tools it shells out to (`resize2fs`, `e2fsck`,
`fsck.fat`, `sgdisk`, `partx`) are provided by the container it runs inside, not
bundled here. The package is fully vendored; `build.yml` sets `network: no`.

## Subcommands

```
storage-resizer check   --disk <dev> [--persist-disk <dev>] [--persist-type ext4|zfs|auto] [--persist-label LABEL] [--need 22G] [--max-full 90] [--sector 512] [--json]
storage-resizer backup  [--persist /persist] [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress] (--target <size> | --grow-only)
storage-resizer shrink  --disk <dev> (--shrink-to <size> | --flag-file <path>) [--persist-label LABEL] [--fix-errors] [--dry-run]
storage-resizer grow    --disk <dev> [--esp 2G] [--imga 10G] [--imgb 10G] [--esp-label LABEL] [--fix-errors] [--dry-run]
storage-resizer restore [--persist /persist] [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress] [--cleanup]
storage-resizer cleanup [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress]
```

### check — pre-flight decision

Reads the GPT and the ext4 superblock (no mount needed) and prints a decision:

| decision | meaning |
|---|---|
| `proceed` | the disk already has the EVE-k geometry (ESP 2 GB, IMGA/IMGB 10 GB) |
| `shrink` | shrink the ext4 `/persist` on the boot disk to free `--need`, then grow |
| `grow` | the boot disk already has ≥ `--need` free tail; grow the partitions without shrinking (also the multi-disk / ZFS-persist case) |
| `insufficient` | cannot make room (persist too full, or ZFS/other-disk persist with no boot free tail); stay on the current flavor |

Output goes to **stdout** (human, or JSON with `--json`); errors to **stderr**.
Multi-disk/ZFS aware: shrink applies only to an ext4 persist on the boot disk;
otherwise the room must come from the boot-disk free tail (`--persist-disk` /
`--persist-type`, which defaults to reading `/run/eve.persist_type`).

### Who decides how much shrink is safe

A shrink to `target = currentSize − need` is allowed only if it clears **two**
bounds:

1. **The resize2fs floor.** `resize2fs` refuses to shrink below the used data
   plus non-relocatable metadata, so the target must leave a margin above the
   used bytes — otherwise the shrink fails mid-flight. The margin is a fixed
   reserve plus a fraction of the partition size, measured by the `resize-bench`
   floor sweep (see `tests/resize-bench`): `target ≥ used + fixedReserve +
   pct × currentSize`.
2. **Operating headroom (`--max-full`).** A flat free-space check is not enough:
   freeing 22 GB from a fairly full fs lands it near 100% full, with no room to
   run. So the result must also be at most **`--max-full`%** full (default
   **90**): `used ≤ max-full% × target`.

The floor margin tends to bind on **small** partitions (where the fixed reserve
is a large fraction of the partition) and the fullness cap on **large** ones.
Example: a 100 GB persist at 70 GB used, freeing 22 GB → 78 GB result → 89.7%
full and well above the floor → allowed; the same fs at 75 GB used → 96% →
rejected by the fullness cap. A 32 GB persist at 8 GB used freeing 22 GB → 10 GB
result is only 80% full but sits below the ~10.65 GB floor → rejected by the
margin. A too-full or too-small device is reported `insufficient` (controller-
visible; the device stays on its current flavor). `check --json` reports
`usedBytes`, `targetBytes`, `resultPercent`, `maxFullPercent`, `marginBytes`,
and `floorEstimateBytes`.

**Margin constants.** They are fitted (with a 1.25× safety factor) to the full
`resize-bench` floor sweep — fill 30/50/70/85/95% × small/mix/aged ×
default/eve/nojournal, 8–64 GB. The worst-case floor-above-used tracks
~1742 MiB + 1.311% of size; the constants in `sizecheck.go` are that fit scaled
by 1.25, giving ~1.25× headroom over the measured upper envelope across the size
range. Note that the sweep also found `resize2fs -P` to predict the achieved
`-M` floor exactly (never under-estimating) at EVE's 4 KiB blocksize — an option
for a future, more precise check, at the cost of depending on the `resize2fs`
binary online (the current check is dependency-free, reading only the
superblock). See `tests/resize-bench` and `~/notes/ext4-floor-sweep0.md` for the
harness and analysis.

### backup / restore / cleanup — surviving a persist wipe

All of these write under `/config`, which **must be the CONFIG partition mounted
read-write by the caller**, not the runtime `/config` (a read-only tmpfs RAM copy
whose writes are lost on reboot — see the note below).

`backup` (online, before the shrink reboot) copies the connectivity-, ssh-, and
device-identity-critical files to `<config-partition>/backup-persist/` and writes
the `<config-partition>/repartition-inprogress` flag file (the target size) **last**.
With `--grow-only` it writes **only** the flag, with the literal value `grow-only`
and no backup: the grow path is non-destructive, so there is no `/persist` to
protect; storage-init reads that value, skips the shrink, and runs only the grow.
If the shrink ever has to recreate `/persist` empty,
`restore` (after `/persist` is remounted) restores each backed-up file whose live
copy is **missing, empty, or invalid for its type** — a cert/key missing its
`-----END` marker, or a DevicePortConfigList that is not valid JSON (truncation
always breaks both). A present, non-empty mutable file (the saved config
`lastconfig`/`.bak`, `controllercerts`) is left untouched, since the live copy
may be a legitimately newer version that the stale backup must not clobber —
pillar validates those itself and falls back to its `.bak` copies. Then
`--cleanup` removes the **flag file first, then the backup dir** (the reverse of
backup's flag-file-last order, so a crash mid-cleanup is safe). The flag file
gates the backup dir: when the flag file is absent, `restore` instead
**garbage-collects** any leftover backup dir without restoring — so stray
`/config` files can't perturb the `measure-config` PCR on the boot that needs the
vault.

`cleanup` is the idempotent end-of-conversion sweep the caller runs after **any**
backup, whether or not a restore was needed. A crash during `restore --cleanup`
can clear the flag file but leave the backup dir behind; once the device reaches
the steady `proceed` state nothing re-runs `restore` to garbage-collect it, so
the dir would linger and keep perturbing the `measure-config` PCR. `cleanup`
removes the backup dir, but only once the flag file is gone — while the flag file
is still present a shrink is pending and the dir holds the only copy of the
device-identity files, so `cleanup` refuses (non-zero exit) rather than risk data
loss.

Backed-up set:
`checkpoint/lastconfig*` (EdgeDevConfig incl. ssh keys + network),
`checkpoint/controllercerts*` (controller signing certs), the device-identity
certs/keys in `/persist/certs/` (`certs/ecdh.*.pem` to decrypt
controller-supplied credentials, and `certs/attest.*.pem` + `certs/ek.*.pem`,
the attestation/endorsement identity the device needs to re-attest and recover
its vault key from the controller), and `status/nim/DevicePortConfigList`. The
`/persist/certs/` keys cannot be re-derived once the filesystem is wiped — only
the controller-trust anchor in `/config` survives the shrink on its own — so
losing them would cost the device its attestation identity, hence the backup.

> The persistent `/config` writes must go through the CONFIG partition mounted
> read-write. At runtime `/config` is a **read-only tmpfs RAM copy** of that
> partition (storage-init copies the partition into RAM, unmounts it, and
> remounts the tmpfs read-only), so writes to the runtime `/config` are lost on
> reboot. The caller must find `PARTLABEL=CONFIG`, mount it read-write at a temp
> path, point `--backup-dir`/`--flag-file` there, write, sync, and unmount (the
> `monitor` agent's `findfs PARTLABEL=CONFIG` pattern). Wiring that mount around
> `backup`/`restore`/`cleanup` is a correctness requirement, not yet implemented.

### shrink / grow — the repartition

Two subcommands driven through `partitionresizer`, run in different contexts:

- **`shrink`** shrinks the persist partition in place to the target (`--shrink-to`
  or `--flag-file`). It needs `/persist` unmounted, so it runs from storage-init
  in early boot.
- **`grow`** grows ESP/IMGA/IMGB into the freed space, preserving their partition
  numbers. It does not need `/persist` unmounted, so it runs from baseosmgr
  (online, the no-shrink case) or from storage-init right after `shrink`.

Each re-plans from the live GPT, so a crash is recovered by re-running.

`--fix-errors` lets `fsck`/`e2fsck` repair the affected filesystem before the
resize (off by default, so a dirty fs fails loudly rather than being silently
mutated). The label and geometry knobs — `check`/`shrink` `--persist-label`,
`grow` `--esp-label`, and `check --sector` (logical sector size, default 512) —
override the built-in defaults and are normally left unset.

## Build

```sh
make pkg/storage-resizer    # linuxkit package build (network: no)
```

For local iteration: `go build` / `go test ./...` in this directory
(`-mod=vendor`).

## See also

`pkg/pillar/docs/diskconvert.md` (the baseosmgr-side orchestration and the
exact Result/error contract), and `tests/resize-bench/` (the offline timing
harness for shrink vs grow).
