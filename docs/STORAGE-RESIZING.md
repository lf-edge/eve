# Storage resizing (boot-disk repartition)

## Purpose

Early EVE installs used a small boot-disk layout — A/B root partitions
(IMGA/IMGB) as small as 300 MB and a correspondingly small EFI System Partition
(ESP). Modern fresh installs use a much larger layout — a 2 GB ESP and two 10 GB
IMG partitions — regardless of hypervisor flavor. A device keeps the partition
sizes it was *installed* with: upgrading an old device to a newer EVE-OS version
replaces the rootfs contents but never repartitions the disk, so a long-lived
device can still be carrying the original small partitions today.

The EVE-k (Kubernetes) rootfs and its container/k3s tooling do not fit in those
old small partitions. So when a user wants to upgrade such a long-lived device to
EVE-k, the small partitions must first be enlarged. The storage-resizing
machinery does this repartition in place — growing ESP/IMGA/IMGB to the larger
geometry, and if necessary first shrinking the `/persist` filesystem to free the
space — so that an in-field device can be converted to EVE-k without re-imaging
and without losing `/persist` data or the device's identity. (A device whose
partitions are already large — a modern fresh install — needs no resize, so the
resizing is a no-op; other aspects of the EVE-k conversion still apply but are
out of scope for this doc.)

This conversion is only attempted when the controller pushes a cross-flavor
base-OS update and the device is in a state where that is allowed. Repartition
is the prerequisite step; the normal A/B install runs afterwards.

The whole machinery is designed to be as robust and reliable as possible, and in
particular to survive inopportune power outages at any point. The one
unavoidable risk is the in-place shrink of the `/persist` filesystem (resize2fs
and e2fsck are not transactional): if power is lost mid-shrink, the worst case is
that `/persist` is lost — its workload data and volumes gone — but even then the
device recovers automatically by recreating an empty `/persist` and restoring
critical parts of `/persist` — such as the device's identity, network
configuration, and ssh configuration — from the backup taken before the shrink,
so it stays bootable and remotely manageable. No failure mode bricks the device.
A milder interruption can instead leave `/persist` intact but with the repaired
subtrees reconnected under `/persist/lost+found`, whose usage EVE reports and
reclaims during the low-disk boot cleanup.

## The four-way decision

Everything keys off a read-only pre-flight check of the live GPT and the
`/persist` superblock, which classifies the disk into one of four outcomes:

| decision | meaning | what happens |
|---|---|---|
| `proceed` | the disk already has the EVE-k geometry | nothing; the install continues |
| `shrink` | `/persist` is an ext4 filesystem on the boot disk and must be shrunk first to free room | back up identity, reboot, shrink+grow offline |
| `grow` | there is already enough free space after `/persist` (a free tail on the boot disk, or `/persist` on a separate disk or ZFS) | reboot, then grow ESP/IMGA/IMGB offline into the free space |
| `insufficient` | room cannot be made (`/persist` too full, or it lives elsewhere with no free tail) | decline the conversion; stay on the current flavor and report it |

A shrink is only judged safe when the resulting filesystem clears two bounds: a
floor (the filesystem cannot be shrunk below its used data plus non-relocatable
metadata) and an operating-headroom cap (after freeing the needed space the
filesystem must still be no more than a configured percentage full). A device
that fails either bound is reported `insufficient` rather than risked — the
conversion declines cleanly and the device keeps running its current flavor.

## Components

- **`storage-resizer`** (`pkg/storage-resizer`) — a standalone binary that does
  all the actual disk work via the external `github.com/diskfs/partitionresizer`
  and `github.com/diskfs/go-diskfs` libraries. It
  is deliberately kept out of the pillar Go module (so those libraries never
  enter pillar) and is invoked as subcommands: a read-only `check` (the
  decision above), `backup`/`restore`/`cleanup` of identity files, and the
  `shrink`/`grow` repartition steps. Its binary is built into both the pillar
  and storage-init images.

- **`diskconvert`** (`pkg/pillar/diskconvert`) — a small pillar library that
  runs the `check` and maps its decision to the next action, *exec*ing the
  storage-resizer binary rather than importing it. It prints nothing and has no
  durable side effects of its own beyond what the subcommands it invokes do; it
  returns the outcome to its caller.

- **baseosmgr** (`pkg/pillar/cmd/baseosmgr`) — the online orchestrator. At the
  cross-flavor seam of a base-OS update, after the target image is downloaded
  and verified but before the A/B partition write, it drives `diskconvert` for
  one conversion step and records progress on `BaseOsStatus`. It also reads the
  failure marker (below) to report a declined conversion and to gate retries.

- **nodeagent** (`pkg/pillar/cmd/nodeagent`) — performs the graceful reboot
  that the shrink case needs. baseosmgr advances a `BaseOsStatus` sub-state;
  nodeagent (subscribed to it) runs its normal node-reboot path — halt apps,
  set the boot reason, sync — rather than baseosmgr resetting directly.

- **storage-init** (`pkg/storage-init`, `storage-resize.sh`) — the offline
  driver. Very early in boot, while `/persist` is still unmounted, it runs the
  `shrink` then `grow`; after `/persist` is mounted it runs `restore` and
  `cleanup`. This is where the destructive shrink can safely happen, and where
  the fail-safe (reboot/abort/marker) logic lives.

- **zedagent / eve-api** — the conversion is reported to the controller as a
  dedicated device state (`CONVERTING`) with sub-states, so an operator can see
  that a device is mid-repartition or that a conversion was declined and why.

A second, important detail of the runtime layout: at runtime `/config` is **not**
the CONFIG partition — it is a read-only tmpfs RAM copy. The backup, the shrink
flag, the reboot counter, and the failure marker must therefore be written to
the CONFIG **partition** mounted read-write, or they would be lost on exactly
the reboot the shrink depends on. Both baseosmgr and storage-init mount the
partition explicitly for these writes.

## Flow — grow only (no shrink needed)

This is the case where there is already enough free space after `/persist`
(a free tail on the boot disk, or `/persist` on a separate disk or ZFS).

The grow cannot be applied while the device is running: the kernel will not
re-read the boot disk's partition table while that disk's own rootfs is mounted.
So the grow runs **offline in storage-init**, exactly like the shrink — only
without the destructive shrink and without the identity backup (the grow is
non-destructive):

1. baseosmgr runs the pre-flight check; the decision is `grow`. It writes the
   `repartition-inprogress` flag on the CONFIG partition with the value
   `grow-only` (no `/persist` backup is taken) and advances the `BaseOsStatus`
   sub-state so nodeagent performs a graceful reboot.
2. Early in the next boot, with `/persist` unmounted, storage-init sees the
   `grow-only` flag, skips the shrink, and grows ESP/IMGA/IMGB into the free
   space — preserving each partition's number, label, PARTUUID, and GPT
   attributes. If the kernel cannot re-read the committed table live (busy boot
   disk) the resizer signals "reboot to apply" and storage-init reboots; the
   repeated boot's grow is a no-op.
3. After `/persist` mounts, storage-init clears the flag. The check re-evaluates
   to `proceed` and the cross-flavor A/B install continues.

The grow is never destructive: it creates the new, larger partitions in the
free tail — partitionresizer labels each with the original name plus a
`_resized2` suffix (`EFI System_resized2`, `IMGA_resized2`, `IMGB_resized2`;
ESP2/IMGA2/IMGB2 for short) — copies into them, and only then renames/reindexes
them back to the canonical labels (`EFI System`/`IMGA`/`IMGB`) and removes the
originals, so a power loss at any point leaves either the old layout or the new
one bootable, never a half-built disk.

## Flow — shrink + grow

This is the case that needs to free space inside an ext4 `/persist` on the boot
disk, so it cannot be done online.

1. **Online, in baseosmgr:** the check returns `shrink`. Before doing anything
   destructive, storage-resizer backs up the connectivity- and
   device-identity-critical files (saved config incl. ssh keys and network,
   controller signing certs, the persisted device-port list for cellular/
   last-resort fallback, the saved device UUID so the device can re-onboard
   against its checkpointed config with no controller reachable, and the
   `/persist/certs/` attestation/decryption keys that cannot be re-derived once
   the filesystem is wiped) to the CONFIG partition, then writes the shrink flag
   file (carrying the target size)
   **last**. baseosmgr advances the `BaseOsStatus` sub-state to request a
   reboot and returns "install must wait".

2. **Reboot:** nodeagent performs a graceful reboot. The download had to happen
   before this point, because the offline pass has no network.

3. **Offline, in storage-init early boot (`/persist` unmounted):** gated on the
   shrink flag file, storage-resizer shrinks the `/persist` partition in place
   to the target, then grows ESP/IMGA/IMGB into the freed space. Each step
   re-plans from the live GPT.

4. **After `/persist` mounts:** storage-resizer restores any backed-up file
   whose live copy is missing, empty, or invalid for its type (so a stale backup
   never clobbers a legitimately newer live file), then cleans up — removing the
   flag file first, then the backup. storage-init also mirrors those deletions
   onto the in-memory `/config` tmpfs so the boot-time measurement of `/config`
   stays at its steady-state value and the TPM-sealed vault still unseals
   locally.

5. The conversion re-evaluates to `proceed` and the cross-flavor base-OS update
   proceeds as a normal A/B install.

## Idempotency and failure handling

The conversion must survive power loss at any point and must never leave a
device bricked (unbootable or unmanageable). The design achieves this not with
transactions but with re-planning, ordering, and a small set of durable markers
on the CONFIG partition. The CONFIG partition is the one reliable early-writable
durable store available before `/persist` and before any network — memlogd's RAM
ring and `/persist` logging are both unavailable that early.

**Re-plan, don't resume.** Every `shrink`/`grow` invocation reads the live GPT
and computes what is left to do, rather than resuming from a saved cursor. A
crash mid-step is recovered simply by running the step again on the next boot;
a step that finds its work already done is a no-op. This makes each step
idempotent.

**Non-destructive grow ordering.** The grow never tears down the original
ESP/IMGA/IMGB until the replacements are fully written and committed. A power
loss during the grow therefore always leaves a bootable layout — either the old
partitions or the finalized new ones.

**Shrink flag gating.** The flag file is written last (after the backup is
complete) and is the single gate for the offline pass. If it is absent, the
restore step instead garbage-collects any leftover backup directory rather than
restoring — so a stray backup can never perturb the next boot. Cleanup removes
the flag first, then the backup, the reverse of the write order, so a crash mid-
cleanup is always safe.

**Committed-but-not-visible GPT.** On a busy boot disk the kernel may refuse to
re-read a freshly written partition table while a sibling partition (the running
rootfs) is mounted. storage-resizer distinguishes this from a real failure: it
returns a dedicated "reboot to apply" status, and storage-init reboots so the
kernel reads the already-committed table on the next boot. The repeated boot's
resize is then a no-op (re-plan sees the work done). A bounded reboot counter on
the CONFIG partition stops a pathological loop.

**Hardware watchdog across the offline pass.** A shrink or grow can legitimately
run longer than the firmware watchdog's timeout. Across the offline pass
storage-init runs a feeder (`storage-resizer run-watchdog`) that keeps
`/dev/watchdog` fed so a slow-but-progressing resize is not reset mid-operation,
and disarms the watchdog once the resize completes. The abort and reboot-to-apply
paths reset the device, which stops the feeder regardless.

**Clean abort, never a brick.** Any genuine shrink/grow failure aborts cleanly
rather than continuing against an inconsistent disk. storage-init writes a small
structured failure marker to the CONFIG partition (recording the failing step,
return code, the running EVE version, and whether `/persist` had to be
recreated), then reboots back onto the unchanged layout, which is still bootable
and manageable. The backup is deliberately retained across the abort so that if
a destructive shrink had already corrupted `/persist`, the abort boot can
recreate `/persist` and restore the device identity into it.

**Retry gating.** The offline resizer is part of the running image, so a
deterministic failure would fail identically on every retry — and each retry
costs a reboot. The failure marker is matched against the running EVE version:
while a marker for the current version is present, neither storage-init nor
baseosmgr re-arms the conversion. baseosmgr reads the marker, reports the
decline to the controller via `BaseOsStatus.Error` (an operator-facing reason
that distinguishes `/persist` preserved from recreated), and clears the marker —
from both the CONFIG partition and the runtime `/config` overlay, so the two
never diverge — when the running image changes (a new image may carry a fixed
resizer) or the controller changes or withdraws the target image, at which point
a retry is allowed again.

The net guarantee: a failed conversion degrades to a clean upgrade-decline that
the controller can see, never to a brick, and the device always boots either
fully converted or fully on its prior layout.

More generally, this illustrates a rule worth applying to any autonomous,
reboot-costing remediation in EVE: report the outcome to the controller, and
bound retries on the *input that failed* (here the running EVE version) so a
deterministic failure self-releases when that input changes rather than
reboot-looping — while never blocking permanently or bricking. A flat retry with
no bound would loop; a permanent block would strand a device a later image could
fix; version-keyed gating plus reporting gives both visibility and a safe,
automatic retry.

## Assumptions about github.com/diskfs/partitionresizer / go-diskfs

The robustness above rests on the lower-level partition and filesystem services
behaving correctly and idempotently. These services come from the external
`github.com/diskfs/partitionresizer` and `github.com/diskfs/go-diskfs`
libraries, which storage-resizer assumes provide:

- **Idempotent, re-runnable resize operations** — given the live disk state,
  re-running a shrink or grow either completes the remaining work or is a no-op,
  never corrupting an already-correct table or filesystem.
- **Atomic, non-destructive partition-table commits** — the new GPT is written
  such that an interrupted write leaves a readable, valid table (old or new),
  and partition relocation copies data before removing the source.
- **Preservation of partition identity across relocation** — number, label,
  PARTUUID, and the 64-bit GPT attributes (which carry EVE's A/B boot state) are
  carried onto relocated partitions, so the bootloader and `zboot` see the same
  geometry afterwards.
- **Faithful distinction between a committed table and a live re-read failure** —
  so the busy-disk "reboot to apply" path is correct rather than masking real
  errors.

storage-resizer treats these as guarantees of the libraries and layers its own
backup/restore, flag gating, abort marker, and reboot bounding on top. If those
guarantees do not hold, the higher-level fail-safes still prevent a brick (the
device aborts to its prior layout), but correctness of the resize itself depends
on the libraries delivering the above.

## See also

- `pkg/storage-resizer/README.md` — the binary and its subcommands.
- `pkg/pillar/docs/diskconvert.md` — the pillar-side orchestration and the
  exact result/error contract.
- `docs/EVE-K.md`, `docs/HYPERVISORS.md` — the EVE-k flavor this conversion
  targets.
