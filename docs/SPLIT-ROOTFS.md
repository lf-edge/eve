# POC: Split Rootfs Implementation

## Overview

This proof-of-concept splits EVE’s monolithic rootfs into two images. The
bootstrap rootfs contains only the pieces required to boot and reach a stable,
minimal system, while the pkgs rootfs holds additional services that can be
loaded later. The motivation is straightforward: the legacy rootfs partition has
a strict size cap for backward compatibility, yet the platform keeps growing
with services and firmware. By isolating essential components in a small
bootstrap image and placing everything else in a separate pkgs image, we stay
under the legacy limit while preserving room for growth.

## Architecture

In the POC, services are divided by startup criticality. The bootstrap rootfs
includes the kernel and init layers, firmware and hypervisor support, storage
and networking setup, security hardening, and core orchestration (for example,
pillar and watchdog). The pkgs rootfs carries non-critical services like
observability and ancillary tooling that can be activated once the system is up.
This split is intentionally conservative for the initial POC; the plan is to
move more services into the pkgs image over time as we validate boot-time
requirements and operational sequencing.

Both images are generated as squashfs files from separate LinuxKit
configurations. The system boots from the bootstrap image as usual. The pkgs
image is not booted directly; it is made available to the running system and
mounted, after which its services are started by existing orchestration.

## Build and Run

The POC uses two LinuxKit YAML templates: `images/rootfs_bootstrap.yml.in` for
the essential stack and `images/rootfs_pkgs.yml.in` for the follow-on services.
These templates are rendered into hypervisor-specific configs under
`images/out/`, assembled into tarballs, and converted into squashfs images. The
bootstrap squashfs is embedded into a bootable disk image, while the pkgs
squashfs is staged for runtime injection.

To produce the artifacts, invoke the make targets that build the bootstrap image
and the pkgs image in the same session so they share the current version stamp.
A typical flow is `make live-bootstrap pkgs_rootfs`, which creates a bootable
`live-bootstrap.qcow2` and a `rootfs-pkgs.img` placed under the build’s
installer directory. If you prefer a single step for both rootfs images, use
`make multi_rootfs`. When running, `make run-bootstrap` starts the VM with the
bootstrap disk only, and `make run-bootstrap-with-pkgs` starts the VM while
exposing `rootfs-pkgs.img` to the guest so it can be mounted and consumed at
runtime.

## Artifacts and Layout

Build outputs are written beneath the versioned directory in `dist/amd64/`. The
bootstrap rootfs squashfs and the pkgs squashfs live under
`dist/amd64/<version>/installer/`. The bootable disk image is produced as
`dist/amd64/<version>/live-bootstrap.qcow2`. Run targets read from the
corresponding versioned paths.

## Pillar: extsloader Agent

The extsloader agent in Pillar coordinates the discovery and activation of
services from the pkgs image.

Extsloader monitors for the presence of a storage device or partition carrying
the pkgs squashfs: this can be a removable drive, an internal partition
provisioned at install time, or, in a VM, a virtual disk exposed by the
hypervisor. Once a candidate device is available, it mounts the image to a
controlled location and scans for descriptors and manifests that describe the
containers, dependencies, and start order. Using this information, it
orchestrates staged activation of services, deferring any that would conflict
with boot-critical operations or that require additional prerequisites.

Dependencies and ordering are enforced by consulting Pillar’s configuration and
the manifest metadata, ensuring services are started in a safe sequence.
Extsloader tracks activation state and reports readiness, partial failures, or
timeouts back to Pillar, enabling observability and recovery. If the pkgs image
is missing or malformed, extsloader backs off and retries with exponential
delays, logs diagnostics, and avoids disrupting already-running bootstrap
services.

## Extsloader: suggested improvements (POC scope)

Extsloader is functional for the POC, but several refinements will help
productionize it while keeping behavior host-agnostic.

Integrity and safety. Before mounting and using the pkgs image, validate that it
is intended for this device and not corrupted. A simple approach is to look for
an accompanying manifest or checksum file next to the image and verify a
signature or hash. If validation fails, log and skip activation, then retry
later without disrupting the bootstrap services.

Resource governance. When activating services, apply cgroup limits and
priorities sourced from manifest metadata to ensure predictable resource usage.
This avoids contention with bootstrap services and keeps overall system
performance stable.

Activation strategy and backoff. For services that fail to start or crash,
implement exponential backoff with jitter to avoid restart storms. Track
activation state and aggregate failures into Pillar’s logs for operators.
Consider dependency-aware sequencing for services that need prerequisites.

Overlay lifecycle. On restart or failure, clean up and re-create overlay mounts
for service rootfs to avoid leaking mount points or leaving stale union state.
Persist minimal diagnostics (timestamps, last error) to aid troubleshooting
across reboots.

Device discovery hygiene. Filter candidate storage devices by expected
filesystem type, label, or size before attempting mounts, reducing noise and
accidental mounts. Keep discovery logic identical on real hardware and VMs: the
pkgs image may arrive via a removable drive, an internal partition, or a virtual
disk.

Configurability. Provide configuration hooks to enable/disable extsloader or
constrain which services are activated from pkgs, allowing gradual rollout and
targeted testing.

## Code Path (High Level)

The Makefile drives rendering of `images/rootfs_*.yml.in` to hypervisor-specific
YAMLs under `images/out/`. A tooling pipeline packages referenced containers
into a tarball and then converts the tar into squashfs (via `mkrootfs-squash`).
The bootable disk is created by embedding the bootstrap squashfs into a GPT
layout that includes EFI and configuration partitions, and then converting the
raw image to qcow2 for QEMU. The `run-bootstrap` target launches QEMU with this
qcow2, while `run-bootstrap-with-pkgs` arranges for the pkgs image to be
accessible (for example, via a vfat injection in a VM or a dedicated partition
on hardware), enabling the bootstrap system to mount it and start its services.
Pillar’s extsloader then discovers the mounted pkgs content, interprets the
manifests, and activates the services accordingly.

## Notes on Running

Run targets do not rebuild artifacts. If a run fails because a file is missing
in the expected build directory, rebuild that specific piece (for example, the
pkgs image or the bootstrap qcow2) and ensure you are referencing the correct
version path.
