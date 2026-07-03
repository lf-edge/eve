# diskconvert

## NAME

**diskconvert** — pillar-side orchestration of the EVE-kvm ⇄ EVE-k boot-disk
repartition, driving the standalone **storage-resizer** binary.

## SYNOPSIS

Library (pillar):

```go
c := &diskconvert.Converter{
    Runner:       diskconvert.BinaryRunner{Binary: "/usr/bin/storage-resizer"},
    PersistLabel: "P3",
}
res, err := c.Run(bootDisk) // bootDisk e.g. "/dev/sda"
```

Underlying command (its binary; not in pillar's module):

```
storage-resizer check   --disk <dev> [--persist-disk <dev>] [--persist-type ext4|zfs|auto] [--need 22G] [--max-full 90] [--json]
storage-resizer backup  [--persist /persist] [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress] (--target <size> | --grow-only)
storage-resizer shrink  --disk <dev> (--shrink-to <size> | --flag-file <path>) [--dry-run]   # storage-init/offline
storage-resizer grow    --disk <dev> [--esp 2G] [--imga 10G] [--imgb 10G] [--dry-run]        # storage-init/offline
storage-resizer restore [--persist /persist] [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress] [--cleanup]
storage-resizer cleanup [--backup-dir /config/backup-persist] [--flag-file /config/repartition-inprogress]
```

## DESCRIPTION

`diskconvert` runs the storage-resizer pre-flight `check` on the boot disk and
maps its decision to the next step, then drives that step. It **execs** the
binary (via the `Runner` interface) rather than importing it, so
go-diskfs/partitionresizer stay out of the pillar module.

It is a **library**: it prints nothing of its own. All results are *returned*
to the caller (baseosmgr). The only durable side effects come from the
storage-resizer subcommands it invokes (writing the `/config` shrink flag file + backup,
or rewriting the GPT).

### CRITICAL: runtime `/config` is volatile — writes there do NOT persist

At runtime `/config` is **not** the CONFIG partition. storage-init mounts the
real `PARTLABEL=CONFIG` (vfat) read-only, copies it into a small **tmpfs (RAM)**
mounted at `/config`, unmounts the partition, and remounts that tmpfs
**read-only** (`pkg/storage-init/storage-init.sh`). So a write to `/config` at
runtime lands in RAM, never reaches the partition, and is **lost on the next
reboot** — exactly the reboot the shrink depends on.

Therefore the backup, the shrink flag file, restore, and cleanup **must operate
on the CONFIG partition mounted read-write directly** — not on runtime `/config`.
The caller mounts it (find `PARTLABEL=CONFIG`, mount it read-write at a temp
path, point `--backup-dir`/`--flag-file` there, write, sync, unmount), the way
the `monitor` agent already does for its `findfs PARTLABEL=CONFIG` writes. Every
default path of `backup`/`restore`/`cleanup` that mentions `/config/...` assumes
this real-partition mount; pointing them at the runtime `/config` tmpfs would
silently lose the shrink flag file and the device-identity backup. This is a
correctness requirement, not an optimization.

### Decision → action

| `check` decision | diskconvert action | `Outcome` returned |
|---|---|---|
| `proceed` | none (geometry already EVE-k) | `OutcomeProceed` |
| `shrink` | `storage-resizer backup --target <T>` (writes `/config`) | `OutcomeRebootForRepartition` |
| `grow` | `storage-resizer backup --grow-only` (writes `/config`) | `OutcomeRebootForRepartition` |
| `insufficient` | none | `OutcomeInsufficient` + error |

For both `shrink` and `grow` the caller must reboot; the repartition runs offline
because the kernel will not re-read the boot disk's partition table while its
rootfs is mounted. On the next boot storage-init runs the offline `shrink`
(target-size flag) then `grow`, or just `grow` (the `grow-only` flag); the device
then re-evaluates and normally reaches `proceed`.

## RETURN VALUES — where the output goes

`Converter.Run` returns `(Result, error)`:

```go
type Result struct {
    Decision     string  // the check decision verbatim
    Outcome      Outcome // Proceed | RebootForRepartition | Insufficient
    Reason       string  // human reason (the check's decisionReason)
    ShrinkTarget string  // new persist size, e.g. "81788928K"; set only for shrink
}
```

| Datum | Produced by | Where it goes | Format | Consumer |
|---|---|---|---|---|
| **decision** | `check` → stdout JSON `decision` | parsed into `Result.Decision` | string | diskconvert / caller |
| **shrink target size** | **computed by diskconvert** (persist partition size − needed) | `Result.ShrinkTarget` **and** written to `/config/repartition-inprogress` by `backup --target` | `"<KiB>K"` | baseosmgr (log/observe) **and** the offline `shrink --flag-file` after reboot |
| **insufficient error string** | `check` → `decisionReason` | `Result.Reason` **and** the returned `error` | string | baseosmgr → *(integration)* `BaseOsStatus.Error` → controller |
| backup files (certs, lastconfig, DPC list) | `backup` | `/config/backup-persist/<relpath>` | file copies | `restore` after `/persist` remount |
| shrink flag file | `backup` (written **last**) | `/config/repartition-inprogress` | `"<size>\n"` | storage-init `shrink --flag-file` |
| new partition geometry | `shrink`/`grow` | boot-disk GPT | partition table | kernel / baseosmgr A/B install |

## storage-resizer command I/O

| subcommand | stdout | stderr | exit | durable effect |
|---|---|---|---|---|
| `check` | report — human, or JSON with `--json` | errors (`read GPT:`, `check:`) | 0 ok / 1 read error / 2 usage | none (read-only) |
| `backup` | — | `backed up N file(s)…; wrote <flag-file>=<target>` | 0 / 1 / 2 | `/config/backup-persist/*`, then the `/config/repartition-inprogress` flag file |
| `shrink` | — | `shrink <label> to <size>` | 0 / 1 / 2 | shrinks the persist partition, rewrites GPT |
| `grow` | — | `grow <label>=…` | 0 / 1 / 2 | grows ESP/IMGA/IMGB, rewrites GPT |
| `restore` | — | `restored N file(s) …` | 0 / 1 | restores backed-up files whose live copy is missing/empty/invalid into `/persist`; flag file absent → GCs the backup dir; `--cleanup` removes the flag file then the backup dir |
| `cleanup` | — | `cleanup: …` on refusal | 0 / 1 | removes the backup dir once the flag file is gone; refuses (exit 1) while the flag file is present |

The `check --json` schema (fields diskconvert reads in **bold**):
`disk`, `diskSizeBytes`, `partitions[]{index,name,**sizeBytes**}`, `persistDisk`,
`persistType`, `largePartitionsInPlace{…}`, `spaceForLargePartitions{ok,freeTailBytes,neededBytes}`,
`shrinkApplicable`, `shrinkReason`, `spaceToShrinkExt{ok,freeBytes,**neededBytes**,…}`,
**`decision`**, **`decisionReason`**.

## FILES

- `/config/repartition-inprogress` — the repartition flag file; contains the
  shrink target size, or the literal `grow-only` for the no-shrink path; written
  last by `backup`, read by the offline `shrink`/storage-init, removed **first**
  by `restore --cleanup` (and it gates the backup dir: flag file absent →
  `restore` GCs the dir, and `cleanup` removes it).
- `/config/backup-persist/` — connectivity-, ssh-, and device-identity-critical
  files copied before the destructive shrink, including the `/persist/certs/`
  attestation/decryption keys the device needs to re-attest and recover its vault
  key (see `storage-resizer` backup set), restored afterwards.

## SEE ALSO

`pkg/storage-resizer` (the binary) and `boot-order-internals.md` for where the
offline `shrink`/`grow` run in storage-init. Integration status, on-device
validation results, and open design questions (TODOs/TBDs) live in the running
design notes outside this repo — see the EVE-kvm→EVE-k design doc.
