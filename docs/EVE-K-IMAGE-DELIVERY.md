# EVE-K Container Image Delivery and EROFS

When EVE is built for Kubernetes (`HV=k`), a node needs a set of control-plane
container images — KubeVirt, CDI, Longhorn, Multus, kube-vip — before it can run
anything. Fetching them from a public registry on first boot is slow, and
impossible on a network that cannot reach one. This document explains how EVE
ships them inside its own image instead, why they are stored as EROFS, and what
that means for a device upgraded from a release that did neither.

Everything here applies to `HV=k` builds only.

## Three changes, kept apart

They fail and are debugged differently, so it is worth not conflating them:

1. **The images ship with EVE.** The build produces an OCI layout of everything
   `kube-init` needs and places it in the rootfs.
2. **Their layers are pre-converted to EROFS at build time**, so the device
   never runs `mkfs.erofs` for them.
3. **The k3s CRI snapshotter is `erofs`**, which is what makes those pre-built
   layers usable as-is.

The first two remove work from first boot. The third is the only one with
consequences for a device that already exists.

## Why EROFS rather than an unpacked tree

The `overlayfs` snapshotter stores a layer as a directory tree, so creating one
means untarring thousands of small files onto `/persist`. With `dirsync` on a
single dom0 vCPU that `fsync` storm was the dominant cost of first boot.

An EROFS layer is one file, written sequentially once and then mounted. It is
also smaller — measured across several images, roughly **0.55x** the space of
the same content unpacked as allocated blocks.

## Zero-copy registration

`kube-init` registers the shipped payload into containerd without copying blobs:
each snapshot's layer file is a symlink into the read-only rootfs. The payload
therefore costs approximately nothing on `/persist`, and a fresh install
performs no image conversion at all.

## Upgrading a device that already has overlayfs snapshots

Such a device has its images unpacked as overlayfs snapshots, which the erofs
snapshotter cannot use.

**containerd does not fail.** Its CRI plugin handles exactly this case: if
preparing a snapshot reports it missing, containerd unpacks the image for the
configured snapshotter and retries, reading only from the local content store.
No network is involved — the layers are converted from blobs already present.

Three properties of that fallback matter when a first pod start after an upgrade
looks like a hang:

- the conversion happens **inside container creation**, under kubelet's
  timeouts, with no progress reporting;
- there is **no duplication suppressor**, so concurrent pods sharing an image
  can each start their own conversion;
- it depends on the compressed layers still being present, i.e. on containerd
  not being configured to discard unpacked layers.

kubelet cannot help: the CRI image store records no snapshotter, so an image it
considers present is never re-pulled, and this fallback is the only path.

### Running out of space

The failure mode is **not** a disk-full error during conversion — kubelet's
eviction manager fires first, at a hard floor of **5% of `/persist`**. A
conversion must fit *above* that floor, not merely fit on the disk. Below it,
pods are evicted with an explicit ephemeral-storage reason; recovery is
automatic once space is returned, but lags by kubelet's eviction-pressure
transition period (5 minutes by default).

For an upgrade to convert without tripping this, `/persist` needs free space
exceeding 5% of the partition plus ~0.55x the existing overlayfs population. The
5% term usually dominates.

## Reclaiming the superseded snapshots

Once the snapshotter is `erofs`, every overlayfs snapshot the previous release
created is dead weight — measured at **several GB** on a real upgrade, against
roughly a tenth of that actually needed in EROFS.

Left alone, the transient cost of conversion is not transient at all: it becomes
the node's new steady state, and every upgraded device permanently loses that
space. `kube-init` therefore deletes them from its per-tick health worker.

**When it runs is the whole design.** Only once the running partition is
*committed*, which `kube-init` learns from pillar's `ZbootStatus`. While an
upgrade is under test EVE can still fall back to the other partition, and that
older rootfs runs the overlayfs snapshotter and needs exactly this state to
start the very same apps. Reclaiming early would leave a revert that boots into
apps which cannot start — the failure the A/B partition scheme exists to
prevent.

The gate reads the partition *state*, not the "test complete" flag. The two
answer different questions: the flag marks the moment a test finished and is
meaningful only during an upgrade, so gating on it would fire the pass in one
narrow window and never again, leaving an interrupted sweep unfinished. The
state describes the standing situation and is also correct on the ordinary boot
where no upgrade is in flight.

Deletion drops the stale garbage-collection label from each image record, then
removes snapshots leaf-first, since a parent cannot go while a child references
it. Anything still held is left for the next boot rather than forced.

Being wrong is bounded: the content store still holds the layers, so a snapshot
deleted in error is re-converted on next use — time, not data. That is also what
makes rollback safe after a reclaim, which is verified rather than assumed: with
the old snapshots gone, a forced fallback to the previous release brings apps
back up, the old rootfs re-unpacking what it needs.

A guard refuses to run when `overlayfs` is what CRI is actually configured with
— someone reverted the config, and then those snapshots are live — and fails
closed when the configuration cannot be read.

## Two kinds of "container app"

Anyone testing or debugging this needs the distinction, because only one kind
goes near the snapshotter. An app with `VirtualizationMode=NOHYPER` becomes a
plain Kubernetes pod whose image CRI resolves through the configured
snapshotter. Anything else becomes a KubeVirt VM whose image pillar converts to
a qcow2 and rolls into a PVC, never reaching the CRI snapshotter at all.

Note that a pod-backed app still pays for the PVC path as well, so both
snapshotters end up populated for it.

## Measuring

One trap makes naive measurement wrong by about a factor of two: an EROFS
snapshot directory contains both the layer image and the mountpoint where that
image is mounted, so a disk-usage walk that crosses into the mount counts the
compressed image *and* its decompressed contents. Keep the walk on one
filesystem, or sum the layer files directly. Layer files that are symlinks
belong to the shipped payload; regular files are images converted on the device.

## Known limitations

- **Native Kubernetes (ZKS) workloads are untested.** Their images take the same
  CRI path as a pod-backed app and are the largest at-risk population, and since
  their Deployments all reschedule at once after an upgrade reboot, they are the
  worst case for the missing duplication suppressor.
- **A conversion performed by CRI is invisible.** It happens inside container
  creation, so a slow first pod start after an upgrade cannot be distinguished
  from a hang.

## See also

- [EVE HV=k](EVE-K.md) — modes, k3s configuration, upgrades.
- `evetest/tests/upgrade/` — `TestSnapshotterUpgrade` covers the pod path, the
  VM path as a control, a forced rollback after the reclaim, and an
  out-of-space run.
