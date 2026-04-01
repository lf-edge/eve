# Split Rootfs Implementation Roadmap

## 1. Purpose and Scope

EVE's rootfs is approaching the partition size limit on legacy devices. This document
defines the complete implementation roadmap for splitting the monolithic rootfs into a
Core Image and an Extension Image, including:

- Making the Core Image hypervisor-agnostic (one image for KVM, Xen, and Kubevirt)
- Security design choices for Extension Image integrity and attestation
- How split rootfs affects every installation method (USB, iPXE)
- How split rootfs integrates with the existing A/B update mechanism
- Relative effort estimation and delivery plan

The security analysis is central. Every architectural choice - where the
Extension Image lives on disk, how it is verified, whether it participates in
TPM measurement and sealing - affects the installation flow, upgrade flow,
and controller integration. These connections are discussed together, not
in isolation.

Effort estimates are relative, using the USB boot priority feature as a calibration point.
That work touched EVE API protobuf definitions, pillar type system, zedagent with LPS
integration, KVM hypervisor layer, UEFI firmware patches (EDK2), and documentation —
approximately 2,700 hand-written lines across 42 files in 6 subsystems over 
~9 weeks of concentrated effort. It is assigned **8 story points** and serves as the
reference for all estimates in this document.

Where controller-side changes are needed, the scope is identified but the work belongs to
a separate team. In current practice, controller handling is typically a single hardcoded
baseline table and customers mainly expect reliable recovery (not per-update PCR forensics).
This lowers expected coordination for normal rollouts. All effort estimates are
device-side unless explicitly marked otherwise.

## 2. Current Baseline: How EVE Boot, Measurement, and Sealing Work Today

Understanding the current security model is essential before evaluating what split rootfs
changes. This section describes what `origin/master` does today.

### Boot Chain

EVE uses a two-stage GRUB architecture:

```
Firmware (UEFI/BIOS)
  └─ Loads 1st-stage GRUB from EFI partition [written once at install, never updated]
       └─ gptprio.next selects highest-priority partition (IMGA or IMGB)
       └─ Chainloads 2nd-stage GRUB from inside the selected squashfs
            └─ measurefs $root --pcr 13    [measures entire rootfs into TPM]
            └─ Loads kernel from squashfs
            └─ Passes root=PARTUUID=<squashfs-partition> to kernel
                 └─ Kernel mounts squashfs directly as read-only root
                      └─ Linuxkit init → containerd → pillar agents
```

The 1st-stage GRUB is the only component that cannot be updated after deployment. All boot
logic, TPM measurement, and hardware detection live in the 2nd stage, which ships with
every rootfs update.

### TPM and PCR Registers

EVE supports devices both with and without TPM. On TPM-enabled devices, attestation and
vault sealing use TPM2 PCR values from the SHA256 bank. In current EVE policy, PCR indexes
0–15 are used for quote and sealing decisions. Each PCR is a 256-bit SHA256 register with
two key properties:

- **Extend-only**: `PCR[n]_new = SHA256(PCR[n]_current || measurement)`. You cannot write
  arbitrary values.
- **Reset only on reboot**: Once extended, a PCR value cannot be undone until power cycle.

Current PCR usage in EVE:

| PCR | Extended By | Contains | In Sealing Set? |
|-----|-------------|----------|-----------------|
| 0–4 | UEFI firmware, GRUB | Firmware, bootloader, kernel | Yes (except 5) |
| 5 | UEFI | GPT partition table, boot manager config | **No** (volatile) |
| 6–7 | UEFI | Secure Boot state, boot variables | Yes |
| 8–9 | GRUB | GRUB commands, binary modules | Yes |
| 10–11 | (unused) | All zeros | Yes |
| **12** | **(unused)** | **All zeros** | **Yes** |
| 13 | GRUB (`measurefs`) | Rootfs squashfs hash | Yes |
| 14 | `measure-config` | /config partition file hashes | Yes |
| 15 | (unused) | All zeros | **No** (reserved for OS/user) |

### Sealing: Disk Encryption Key Protection

EVE seals the disk encryption key (for `/persist/vault/`) to specific PCR values. The TPM
only releases the key if current PCR values match the values recorded at seal time.

**Default sealing PCR set** (from `pkg/pillar/evetpm/tpm.go:120-135`):

```
{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14}
```

This is all PCRs from 0 to 14, excluding PCR 5 (volatile GPT state) and PCR 15 (OS/user-defined).

**Critical detail**: PCRs 10, 11, and 12 are currently all-zeros because nothing extends
them. Sealing works because zero is a consistent, reproducible value. If any code begins
extending one of these PCRs, the sealed value changes, and vault unsealing fails on next
boot. This is not a bug — it is an intentional property of measured boot. In split-rootfs
design, any decision to measure Extension into one of these currently-zero PCRs requires
explicit rollout and unseal-order handling.

The controller can also provide a custom PCR policy (via `VaultKeyPolicyPCR`) that overrides
the default. This is the mechanism for planned PCR policy changes during rollout.

### Attestation: How the Controller Verifies Device State

EVE periodically proves to the controller what software is running:

1. Controller sends a nonce (random challenge).
2. Device asks TPM to sign all 16 PCR values together with the nonce.
3. Device sends the signed quote back to controller.
4. Controller validates: signature from real TPM, nonce is fresh, PCR values match
   expected baseline.

**Attestation quotes include all PCRs 0–15** (`PcrListForQuote` in
`pkg/pillar/evetpm/tpm.go:171`), including currently-unused PCRs like 10, 11, 12. This
means the controller already sees these zero-valued PCRs and has baselines for them.

### PCR Baseline Management

The controller uses "trust on first use with operator approval":

- **First boot**: Device sends PCR values. Operator reviews and accepts as baseline.
- **Normal operation**: PCR values match baseline. Attestation passes automatically.
- **PCR change** (e.g., after EVE update): Controller flags mismatch. Operator reviews
  and accepts new baseline (routine for expected updates).

### Update and Vault Recovery

When EVE is updated, PCR values change (new kernel, new rootfs). The vault key sealed to
old PCR values cannot be unsealed. Recovery uses a two-party key escrow:

1. Encrypted backup of vault key is stored on controller.
2. After update + reboot, device re-attests with new PCR values.
3. Controller checks if new values match a known EVE version profile.
4. If recognized: automatic recovery — controller sends encrypted backup key.
5. Device decrypts backup, re-seals vault key to new PCR values.
6. If not recognized: blocked until operator reviews.

This mechanism already exists and works for PCR 13 changes (rootfs updates). Any new PCR
measurement (for Extension Image) would follow the same recovery path — as long as the
controller is aware of the new PCR behavior.

### What This Means for Split Rootfs

In master today, all services that would move to Extension are inside the monolithic rootfs.
They are covered by PCR 13 measurement (GRUB measures the entire squashfs). After split:

- Core Image stays in IMGA/IMGB, measured into PCR 13 by GRUB. No change.
- Extension Image is a separate artifact. Its security posture depends on design choices
  covered in the rest of this document.

The key question is not "is Extension secure?" but rather "which security model provides
the required assurance, and what does it cost to implement safely?"

## 3. Problem Statement

### The Immediate Problem

EVE's rootfs is approaching partition size limits:

| Variant | Current Size | Limit | Headroom |
|---------|-------------|-------|----------|
| amd64-kvm-generic | ~277MB | 300MB | 23MB |
| arm64-kvm-nvidia-jp6 | ~446MB | 512MB | 66MB |

Legacy devices (pre-10.10.0) have 300MB partitions; newer installations (including
nvidia JP6) default to 512MB. CVE fixes and new dependencies are consuming the
remaining space. Generic variants on legacy partitions are closest to the limit — some
cannot receive routine security updates without partition resizing.

### Why 300MB?

The limit exists for backward compatibility. EVE 10.10.0 increased the default to 512MB
for new installations, but devices deployed before that release still have the old partition
layout. Resizing requires maintenance windows that operators may not schedule for urgent
CVE patches. The installed base of 300MB devices is a hard constraint.

### The Strategic Problem

EVE currently produces many different builds for different hypervisor and hardware
combinations. A modular approach — one base image with pluggable extensions — would reduce
build matrix complexity and simplify fleet management.

### What Can Move Out of Rootfs

Analysis of the rootfs content shows which packages can move to a separate image.
The POC Extension template (`images/rootfs_ext.yml.in`) defines the package set:
eve-debug, eve-vtpm, eve-wwan, eve-vector, eve-kube (HV=k only), guacd, edgeview,
memory-monitor, node-exporter.

Size estimates below are derived from build experiments on `master` at commit `94c51ee`
(see *Single Image Evaluation* report). The experiments measured effective rootfs size
reduction by removing package subsets and rebuilding. Because container layers are shared,
savings are not a simple sum of individual image sizes — each row was measured as a group.
The experiment's package sets do not match the POC exactly (see notes), so actual savings
need validation with the final Extension build.

| Variant | Measured Savings | Resulting Core | Notes |
|---------|-----------------|----------------|-------|
| amd64-kvm-generic | ~38MB → ~239MB | from ~277MB | Experiment removed eve-wwan, eve-debug, eve-vtpm. POC Extension adds vector, guacd, edgeview, memory-monitor, node-exporter — actual savings will be larger. |
| arm64-kvm-generic | ~35MB → ~218MB | from ~253MB | Same as above. |
| arm64-kvm-nvidia-jp6 | ~166MB → ~280MB | from ~446MB | Experiment removed eve-nvidia in addition to the Extension set. POC does not move eve-nvidia — actual savings will be smaller. |
| amd64-kubevirt-generic | ~112MB → ~268MB | from ~380MB | Experiment removed eve-wwan, eve-kube. POC Extension adds more packages — actual savings will be larger. |

Generic variants on legacy 300MB partitions are the most space-constrained. The measured
~38MB saving is a lower bound — the full POC Extension set moves additional packages and
will save more. The nvidia variant is the most challenging: without moving eve-nvidia,
it may not fit under 300MB (but it uses 512MB partitions, so the constraint is softer).

### Two Problems, One Solution

Split rootfs addresses both problems simultaneously: it keeps Core under the partition
limit, and when combined with a generic (HV-agnostic) Core Image, it reduces the build
matrix to one core artifact per architecture.

## 4. Generic Core Image: One Image for All Hypervisors

### Why This Matters for Split Rootfs

If Core Image remains hypervisor-specific (separate builds for KVM, Xen, Kubevirt), the
split produces N core images times M extension images. Making Core generic means one core
image per architecture, with HV selection at runtime. This simplifies:

- **Build system**: one Core build target instead of per-HV targets
- **Security**: one PCR 13 baseline per architecture, not per HV variant
- **Fleet management**: one update package per architecture
- **Testing**: one boot path to validate

### Key Insight: KVM, Xen, and Kubevirt Share Binaries

Analysis of the pillar codebase shows that the same Go binary can run on all three
hypervisors. Today, the `//go:build k` tag conditionally compiles Kubevirt-specific code —
without this tag, `kubeapi/`, `cmd/zedkube/`, and related files are excluded from the build.
This produces different binaries for different HV types.

**The goal is to eliminate build tags entirely and produce one identical binary.** All
Kubevirt-specific code is compiled unconditionally. HV-specific behavior is gated purely
at runtime by reading `/run/eve-hv-type`. This guarantees that the Core Image is
byte-identical across KVM, Xen, and Kubevirt deployments on the same architecture.

Xen packages (xen.gz, xen-tools) are already included in all rootfs variants regardless
of HV type. Once pillar is also HV-agnostic, the entire Core Image becomes universal.

> **Current limitation (PoC):** The `eve-split` Makefile target builds Core and Extension
> for a specific hypervisor (`HV=kvm` by default). The kernel, Xen tools, and HV modifiers
> applied by `compose-image-yml.sh -h $(HV)` are baked at build time. While pillar is
> already universal (`PILLAR_K_TAG`), achieving a truly HV-agnostic Core Image requires:
> (1) bundling kernels/tools for all supported HVs into the Core, and (2) selecting the
> active HV at boot via the CONFIG partition `eve-hv-type` flag — similar to how
> `live-split-k` works today. This is tracked as a follow-up to the initial split-rootfs
> implementation.

### Runtime Guard Architecture

With build tags removed, all HV-specific code is always present in the binary. Safety is
ensured by runtime guards:

**Runtime guard** (`pkg/pillar/kubeapi/runtimeguard.go`): Every exported function in the
kubeapi package calls `ensureKubeRuntime()`, which checks `base.IsHVTypeKube()`. If the
HV type is not `k`, the function returns an error immediately. This prevents Kubevirt code
from executing on KVM/Xen devices.

```go
// pkg/pillar/kubeapi/runtimeguard.go
func ensureKubeRuntime(op string) error {
    if base.IsHVTypeKube() {
        return nil
    }
    return fmt.Errorf("%s: kube runtime is not enabled", op)
}
```

Runtime detection reads from `/run/eve-hv-type` (`pkg/pillar/base/kubevirt.go`, constant
`EveVirtTypeFile`).

Why we keep `/etc`, `/run`, and `/config` versions of `eve-hv-type`:
- `/etc/eve-hv-type` is the baked-in default in the Core Image (`images/rootfs_core.yml.in`).
- `/config/eve-hv-type` is an optional post-build override (for example from installer/ZFlash).
- `/run/eve-hv-type` is the effective runtime value consumed by pillar/hypervisor code.

Boot sequence with explicit actors and files:
1. **GRUB** (`pkg/grub/rootfs.cfg`, function `set_eve_flavor`) reads `eve-hv-type` from CONFIG if
   present, else from `($root)/etc/eve-hv-type`, and stores it in GRUB variable `eve_flavor`.
   We need `eve_flavor` because GRUB must pick the pre-kernel boot path (`set_${eve_flavor}_boot`)
   before Linux kernel/userspace exists.
2. **Linux kernel** starts PID 1, and EVE's **LinuxKit init stage** (declared in
   `images/rootfs_core.yml.in`, `init:` list with `linuxkit/init` and `DOM0ZTOOLS_TAG`) starts
   early userspace. At this stage, `/run` exists as runtime writable filesystem space.
3. **dom0-ztools init script** `pkg/dom0-ztools/rootfs/etc/init.d/009-id` copies
   `/etc/eve-hv-type` to `/run/eve-hv-type` (initial runtime value).
4. **LinuxKit onboot ordering** (also from `images/rootfs_core.yml.in`) runs `storage-init` before
   `pillar-onboot`.
5. **storage-init** (`pkg/storage-init/storage-init.sh`) mounts CONFIG, creates RAM-backed
   `/config`, and reads `/config/eve-hv-type` for ext4/ZFS storage decisions.
6. **pillar-onboot** (`pkg/pillar/scripts/onboot.sh`) overwrites `/run/eve-hv-type` from
   `/config/eve-hv-type` if the override file exists.
7. **Runtime agents** (for example `pkg/pillar/base/kubevirt.go`,
   `pkg/pillar/hypervisor/hypervisor.go`, `pkg/pillar/scripts/device-steps.sh`) read
   `/run/eve-hv-type`.

### CONFIG Partition as HV Selector

The same value is consumed at different phases by different components:

```
GRUB phase (pre-kernel):
  /config/eve-hv-type (fallback: /etc/eve-hv-type) → eve_flavor → set_${eve_flavor}_boot

Linux early runtime:
  /etc/eve-hv-type → /run/eve-hv-type   (seed by 009-id)

Linux onboot phase:
  /config/eve-hv-type (if present) → /run/eve-hv-type   (override by onboot.sh)

Runtime agents:
  read /run/eve-hv-type
```

Related consumers:
- `storage-init.sh` reads `/config/eve-hv-type` to select ext4/ZFS behavior.
- Pillar/hypervisor runtime code reads `/run/eve-hv-type`.

Files/scripts involved in this flow:
- `pkg/grub/rootfs.cfg`: `set_eve_flavor`, `set_${eve_flavor}_boot`.
- `images/rootfs_core.yml.in`: declares `init` and onboot order (`storage-init` before `pillar-onboot`).
- `pkg/dom0-ztools/rootfs/etc/init.d/009-id`: seeds `/run/eve-hv-type` from `/etc/eve-hv-type`.
- `pkg/storage-init/storage-init.sh`: mounts CONFIG and uses HV type for storage behavior.
- `pkg/pillar/scripts/onboot.sh`: optional override `/config/eve-hv-type` -> `/run/eve-hv-type`.
- `pkg/pillar/base/kubevirt.go`: runtime HV detection source (`/run/eve-hv-type`).

This means HV selection happens at flash time (via ZFlash) or install time (via CONFIG
partition content), not at build time. A single installer image supports all HV types.

### Security Implication

With a generic Core Image, PCR 13 produces the same value on all devices running the same
EVE version on the same architecture, regardless of HV type. This simplifies attestation
baseline management: the controller maintains one expected PCR 13 value per
{architecture, version} pair, not per {architecture, version, HV} triple.

### What Needs to Change (from master)

| Area | Change | Scope |
|------|--------|-------|
| `pkg/pillar/kubeapi/` | Add runtime guards to all exported functions | ~50 call sites |
| `pkg/pillar/hypervisor/kubevirt.go` | Add `IsHVTypeKube()` fail-fast checks | ~5 entry points |
| `pkg/pillar/cmd/zedkube/` | Gate startup by HV type | Startup check |
| `pkg/pillar/cmd/zedmanager/` | Conditional subscription to ENClusterAppStatus | 1 subscription |
| `pkg/pillar/cmd/volumemgr/` | Gate PVC disk metrics by HV type | 2 checks |
| All `//go:build k` files | **Remove build tags** — compile unconditionally | ~20 files |
| `pkg/pillar/scripts/device-steps.sh` | Conditional zedkube agent startup | Shell check |
| `pkg/pillar/scripts/onboot.sh` | Propagate CONFIG eve-hv-type to /run | File copy |
| `pkg/storage-init/storage-init.sh` | Select ext4/ZFS based on HV type | Shell check |
| `pkg/grub/rootfs.cfg` | Read eve-hv-type from CONFIG | GRUB variable |
| `images/rootfs_core.yml.in` | Single pillar binary (no HV-specific builds) | Template change |
| `Makefile` | Remove per-HV pillar targets, add split targets | Build cleanup |

Removing build tags requires verifying that all kube-specific code paths are properly
guarded at runtime. Any function that currently relies on "this code is only compiled for k"
must have an explicit runtime check added. This is methodical but must be thorough — a
missed call site could attempt kube operations on a KVM device.

**Effort estimate: 2 story points development** (device-side only; Eden testing in
Section 10). Smaller than USB boot priority's development portion (~3 SP): mostly
mechanical runtime guard insertion (~50 call sites, each following the same pattern),
build tag deletion (~20 files), and GRUB/shell plumbing. POC `runtimeguard.go` already
exists. No API proto changes, no firmware patches, no LPS integration.

## 5. Split Rootfs Architecture

### Overview

The monolithic rootfs is split into two images:

- **Core Image** (~240MB, squashfs): Kernel, init, pillar, containerd, networking, firmware,
  Extension Loader. Lives on IMGA/IMGB partitions. Measured into PCR 13 by GRUB.

- **Extension Image** (erofs + dm-verity): Non-critical services — eve-debug, eve-vtpm,
  eve-wwan, eve-vector, memory-monitor, edgeview, guacd, node-exporter, eve-kube (HV=k
  only). Lives on PERSIST partition. Loaded after boot by Extension Loader.

### Image Format

Core Image stays squashfs — the entire boot chain depends on it (GRUB reads from it,
kernel mounts it directly).

Extension Image uses erofs + dm-verity. erofs is a read-only filesystem designed for fast
mount and page-aligned access. dm-verity provides a Merkle hash tree that validates every
block read from the filesystem. The combination means:

- At build time: erofs image is created, dm-verity hash tree is generated and appended,
  root hash is recorded.
- At runtime: Extension Loader sets up a loop device, calls `veritysetup` with the trusted
  root hash, mounts the verified device read-only.
- Any modification to the underlying file causes dm-verity to return I/O errors on affected
  block reads.

**Why not squashfs for Extension?** squashfs provides one-time verification (check hash at
mount time). dm-verity provides continuous block-level verification. Since Extension lives
on a writable partition (PERSIST), dm-verity matters: an attacker who gains write access to
PERSIST cannot inject modified content without triggering I/O errors. With squashfs alone,
modifications would go undetected until the next reboot's hash check.

### dm-verity Root Hash Trust Chain

The dm-verity root hash is embedded in the Core Image at build time
(`/etc/ext-verity-roothash`). Since the Core squashfs is measured into PCR 13 by GRUB,
the root hash is transitively protected by the TPM-measured boot chain:

```
PCR 13 (GRUB) seals Core squashfs
  └─ Core squashfs contains /etc/ext-verity-roothash
      └─ dm-verity validates every block of Extension erofs
          └─ overlay lowerdir points into verity-mounted erofs
              └─ containerd runs services from this overlay
```

This means Core and Extension are cryptographically bound: changing Extension requires
changing Core (new root hash), which changes PCR 13 (new squashfs hash). They are always
the same version.

### Why the dm-verity Root Hash Is Sufficient as Extension Identity

The dm-verity root hash is the top of a Merkle hash tree computed over every block of the
Extension erofs image. Changing any block in the image changes the root hash. This makes
the root hash a complete cryptographic identity of the image content — equivalent in
security strength to a SHA256 hash of the entire file, but with two advantages:

1. **No full-file read required.** The root hash is computed once at build time and is a
   compact 32-byte value. At runtime, the kernel verifies blocks on demand (only when read).
   Computing a separate SHA256 of the entire image file would require reading the full image
   (hundreds of MB) into page cache, consuming significant memory inside the pillar cgroup
   for no additional security value.

2. **Measures what is actually verified.** The root hash is the exact value that
   `veritysetup open` uses to validate the Extension image. If `veritysetup open` succeeds,
   the kernel has confirmed the image matches this root hash. A separate SHA256 computed by
   reading the raw file on PERSIST bypasses dm-verity and does not prove that the dm-verity
   device was set up correctly or that runtime reads are protected.

For these reasons, the root hash (not a separately computed file hash) is used for PCR12
measurement. After successful dm-verity mount, extsloader extends PCR12 with the root hash
that was loaded from Core. This completes the trust chain: PCR 13 protects the root hash
(via Core), PCR 12 records that extsloader successfully verified and mounted an Extension
matching that root hash, and dm-verity enforces block-level integrity at runtime.

**Important:** The root hash must only be loaded from the Core Image
(`/etc/ext-verity-roothash`), never from files on PERSIST. The Core-embedded root hash is
the sole trust anchor for Extension identity. The file contains two lines: the root hash
(hex) and the data size in bytes (used as `--hash-offset` for `veritysetup open`, since
the Merkle tree is appended directly to the extension image — no separate hash tree
sidecar file).

### Signing vs Just Hashes for `ext.img`

Current EVE verifier flow is hash-based: `VerifyImageConfig/Status` and verifier logic
verify SHA256 of downloaded content (`pkg/pillar/types/verifiertypes.go`,
`pkg/pillar/cmd/verifier/lib/verifier.go`). For split rootfs, the dm-verity root hash
embedded in Core provides both integrity verification and version binding, making a
separate file-level SHA256 computation redundant at runtime.

| Model | What it gives | Practical note |
|------|---------------|----------------|
| dm-verity root hash in Core (this roadmap baseline) | Version binding + continuous runtime tamper detection on PERSIST | Root hash is the Merkle tree top — any block change invalidates it. No full-file read needed. |
| + Detached signature for `ext.img` (hardening option) | Publisher authenticity bound to a signing key, independent of digest transport | Additional verification step and key lifecycle management |

Related precedent: in the `eve-kernel` tree, module signing is enforced in x86 defconfigs
(`CONFIG_MODULE_SIG=y`, `CONFIG_MODULE_SIG_FORCE=y`, `CONFIG_MODULE_SIG_SHA256=y` in
`arch/x86/configs/eve-core_defconfig` and `arch/x86/configs/eve-hwe_defconfig`).

Recommendation for split-rootfs v1 remains: keep dm-verity root hash (baked into Core) +
PCR12 measurement path as baseline. A detached `ext.img` signature is a valid
defense-in-depth step, but treat it as explicit hardening scope (not implicit in the
current estimates unless added).

### Extension Loader (extsloader)

The Extension Loader is a pillar agent inside Core that manages the Extension lifecycle:

1. Wait for PERSIST to be accessible
2. Determine active partition (IMGA or IMGB) via `zboot.GetCurrentPartition()`
3. Find Extension Image at the corresponding path
4. Read dm-verity root hash and data size from `/hostfs/etc/ext-verity-roothash`
   (Core Image only — never from files on PERSIST)
5. Set up dm-verity device (`veritysetup open --hash-offset=<data-size>` using the same
   image file as both data and hash device, with the Core-embedded root hash)
6. Mount verified erofs read-only at `/persist/exts`
7. Extend PCR12 with the root hash (on TPM-enabled devices; no-op without TPM)
8. For each service: mount overlay (lowerdir from verity-mounted erofs, upperdir on
   PERSIST) and start via containerd (filtered by HV type for kube-specific services)
9. Periodically verify running services, restart if needed

The runtime file access chain is:

```
/persist/ext-imga.img (erofs data + appended Merkle hash tree, on writable PERSIST)
  → veritysetup open --hash-offset=<data-size> (root hash from Core)
    → /dev/mapper/exts-verity-ext-imga-img (dm-verity verified block device)
      → /persist/exts/ (read-only erofs mount, every read verified by kernel)
        → overlay lowerdir=/persist/exts/containers/services/<name>/lower
          → containerd runs service from overlay rootfs
```

Every file read by a running service passes through dm-verity. Tampering with the raw
image on PERSIST causes kernel I/O errors on the affected blocks — services cannot
silently execute modified code.

### Graceful Degradation

If Extension fails (missing, corrupted, verification failure), the device enters degraded
mode:

- **Running**: nim, zedagent, baseosmgr (controller communication + update capability)
- **Not running**: Extension services, workload VMs and containers
- **Purpose**: Device stays reachable so operator can push update or trigger rollback

Degraded mode is intentionally conservative: no workloads run, reducing the risk surface
when part of the platform is not verified.

### Core vs Extension Service Allocation

**Core Image**: kernel, init, firmware, pillar (nim, zedagent, domainmgr, volumemgr,
baseosmgr, etc.), containerd, networking (wlan, dnsmasq), Extension Loader
(extsloader), watchdog, monitor, apparmor, measure-config.

**Extension Image** (from `images/rootfs_ext.yml.in`): eve-debug, eve-vtpm, eve-wwan,
eve-vector, memory-monitor, node-exporter, edgeview, guacd, eve-kube (HV=k only).

### Kernel Module and Firmware Deferred Loading

When the rootfs splits, some kernel modules and firmware blobs currently in the
monolithic image may belong in the Extension Image. The Core initramfs only needs
modules essential for booting and mounting the root filesystem. Additional drivers
can be loaded after extsloader mounts the Extension Image.

Linux supports deferred probing natively: drivers return `-EPROBE_DEFER` when
dependencies (firmware files, bus modules) are not yet available. The kernel
re-attempts probe later. Once the Extension Image is mounted and its module/firmware
paths are visible, udev re-triggers device enumeration and deferred drivers bind
successfully.

**Approach (multi-step module loading)**:

1. Core initramfs/rootfs carries boot-critical modules only (storage, network for
   controller connectivity, TPM)
2. Extension Image carries additional modules and firmware
3. After extsloader mounts Extension, udev coldplug re-trigger loads deferred drivers
4. Services depending on those drivers start after module loading completes

This is a parallel initiative (Avi's firmware/driver loading work) alongside the
split-rootfs service extraction. Both need to be implemented and deployed.

**PoC validation required**: Before finalizing which modules move to Extension, test
udev-based deferred loading for candidate drivers on real hardware:

- Identify drivers in current rootfs that support `-EPROBE_DEFER` vs those that
  fail hard without firmware at initial probe time
- Build a test image with selected modules removed from Core and available only
  via a secondary mount point (simulating Extension)
- Validate udev coldplug re-trigger successfully loads the deferred drivers
- Measure any boot-time impact from the two-phase module loading
- Document which driver categories (network, GPU, USB, wireless) are safe to defer

**Build system consideration** (Erik's point): Moving modules to Extension may
initially duplicate some firmware/drivers at the Core/Extension boundary. The first
step is to validate the basic deferred-loading mechanism; build optimization to
eliminate duplication follows once the module split boundary is established.

### Build System

Two Linuxkit YAML templates define the split content:

- `images/rootfs_core.yml.in` — Core: full bootable Linuxkit spec (kernel, init, onboot,
  services, files) using the universal pillar binary.
- `images/rootfs_ext.yml.in` — Extension: services-only manifest (no kernel, no init).
  Lists the OCI containers to include in the Extension Image.

**Core Image build** follows the existing pipeline: `linuxkit build -o tar` produces a tar
of the rootfs tree, which is piped into `pkg/mkrootfs-squash` to create a squashfs image.
No changes to the existing flow.

**Extension Image build** requires a new pipeline. LinuxKit can extract the service
containers from `rootfs_ext.yml.in` into a tar, but the conversion to erofs is not part
of the existing EVE build tooling. The build system needs:
- `mkfs.erofs` added to the build tools (either a new `pkg/mkrootfs-erofs` package
  following the pattern of `pkg/mkrootfs-squash`, or a standalone build script)
- `veritysetup` to generate the dm-verity hash tree (appended to the erofs image) and
  root hash
- A build step that embeds the root hash and data size into the Core Image
  (`/etc/ext-verity-roothash`) before creating the Core squashfs

This creates a build ordering dependency: Extension Image must be built first (to produce
the root hash), then Core Image is built with the root hash embedded.

Build: `make split_rootfs` produces both `rootfs-core.img` and `rootfs-ext.img`.

## 6. Chosen Security Model

For implementation planning, this roadmap uses one fixed model:

- Extension is measured in userspace into PCR12 after verification.
- PCR12 is included in enforced sealing policy.
- Extension is stored on PERSIST as A/B files: `/persist/ext-imga.img` and
  `/persist/ext-imgb.img`.

Short note on alternatives: other models were evaluated earlier and rejected. This
document does not plan or estimate them.

### Extension Measurement and Attestation on PCR12

Extension Loader extends **PCR 12** after Extension verification/mount.

Why PCR12:
- PCR12 is already in default EVE sealing set (`DefaultDiskKeySealingPCRs`).
- PCR12 is currently unused (zero), so it is available without adding a new PCR family.
- This gives direct coupling between Extension state and vault unseal behavior.

Attestation already quotes PCR 0-15, so PCR12 becomes controller-visible immediately.

Expected progression:

```
Boot starts:            PCR12 = 0x0000... (loader not run yet)
Loader starts:          PCR12 = extend(0, "extsloader:starting")
Image verified+mounted: PCR12 = extend(prev, "extsloader:image-verified:<root-hash>")
Services running:       PCR12 = extend(prev, "extsloader:services-running")
Failure case:           PCR12 = extend(prev, "extsloader:failed:<reason>")
```

The `<root-hash>` is the dm-verity root hash loaded from Core (`/etc/ext-verity-roothash`).
This is the same root hash used by `veritysetup open` to set up the dm-verity device. It
uniquely identifies the Extension image content (it is the Merkle tree root — any block
change changes this value). No separate SHA256 computation of the raw image file is needed;
see "Why the dm-verity Root Hash Is Sufficient as Extension Identity" in Section 5.

On devices without TPM, `extendPCR12` is a no-op. dm-verity still provides runtime
integrity: the root hash is trusted because it is embedded in the read-only Core squashfs,
and `veritysetup open` fails if the Extension image does not match.

Extsloader should also emit compact Extension measurement-log context (same pattern as
`measure-config`) and append it to attestation payload context.

### Sealing Coupling and Boot Ordering Contract

Vault unseal behavior is intentionally coupled to PCR12 state.

Implementation contract for deterministic behavior:
1. `extsloader` performs final PCR12 extend for the boot attempt and writes a readiness
   signal (file or pubsub state).
2. `vaultmgr` must wait for that readiness signal (or terminal failure state) before the
   unseal decision path.
3. Timeout/failure path must be deterministic and must not create reboot/recovery loops.

Note on current behavior: both `extsloader` and `vaultmgr` are started by the same
`zedbox` process, but as separate asynchronous agents. Existing
`vaultmgr waitUnsealed`/`wait.WaitForVault` logic is used by other components to wait
for vault readiness; it does not enforce `extsloader -> PCR12 extend -> vaultmgr unseal`
ordering. Without an explicit handshake, race conditions can trigger repeated recovery
behavior during upgrades.

### Extension Placement on PERSIST

Chosen paths:
- `/persist/ext-imga.img`
- `/persist/ext-imgb.img`

Implications:
- Extension is available early after reboot.
- Physical-access DoS (delete/corrupt file on PERSIST) remains possible, as with many
  other physical-access vectors.
- dm-verity still blocks silent code injection and detects tampering at read time.

## 7. Installation Flows

Every install path must deliver both images:
- Core Image -> IMGA partition
- Extension Image -> PERSIST file (`/persist/ext-imga.img`)

### Current Installation Baseline

Today installer writes one `rootfs.img` to IMGA via `pkg/installer/install`.
Partition layout and flow come from `make-raw` and installer scripts.

### Split Installation Flow

```
1. Boot installer (USB or iPXE)
2. Detect target disk
3. Create GPT layout (EFI, IMGA, IMGB, CONFIG, P3)
4. Write Core Image to IMGA
5. Initialize PERSIST
6. Copy /bits/rootfs-ext.img -> /persist/ext-imga.img
7. Write CONFIG partition
8. Mark IMGA bootable
```

`images/installer.yml.in` must include Extension artifact binding:

```yaml
- path: /rootfs-ext.img
  source: rootfs-ext.img
  optional: true
```

Installer copy logic:

```bash
if [ -f /bits/rootfs-ext.img ]; then
    cp /bits/rootfs-ext.img /persist/ext-imga.img
fi
```

### USB and iPXE

- **USB**: normal production path; ZFlash prepares media, installer executes on device.
- **iPXE/network**: same installer script path, but should be re-validated due to known
  fragility in existing iPXE tooling.

### Installation Effort

- Device effort: **0.5 SP**
- Scope: installer copy path, media recipe update, install validation

## 8. System Upgrade Flow

Split updates always carry Core+Extension together (same version). No Extension-only
upgrade track.

### Update Package Format: OCI Content Tree with Multiple Layers

The existing OCI Content Tree format already supports multiple layers with role
annotations (edge-containers `Artifact` structure). The BaseOS OCI image is extended
from one layer to two:

```
OCI Image Manifest (single ContentTree, single content_tree_uuid)
  ├─ Layer 1: role="disk-root"        → Core squashfs     (existing)
  └─ Layer 2: role="disk-additional"  → Extension erofs   (new)
```

**No eve-api proto change needed.** The `BaseOS.content_tree_uuid` still references a
single ContentTree. The controller publishes one OCI image that now contains two layers.
The `Blobs []string` field in `ContentTreeStatus` already tracks both layer digests.

Build-side change: add one label to `pkg/eve/Dockerfile.in`:

```dockerfile
LABEL org.lfedge.eci.artifact.root="/bits/rootfs.img"
LABEL org.lfedge.eci.artifact.initrd="/bits/initrd.img"
LABEL org.lfedge.eci.artifact.disk-0="/bits/rootfs-ext.img"
```

On the device side, `WriteToPartition` (using edge-containers) is **not modified**.
It writes `disk-root` to the partition as before, and silently skips `disk-additional`
(empty handler in `target.go:191`). Edge-containers is a vendored third-party library
and is not changed.

Instead, a separate function reads the Extension blob directly from containerd CAS
(Content Addressable Storage). All OCI layers — including `disk-additional` — are
already stored in CAS by volumemgr during download. The Extension extraction uses
EVE's existing CAS client (`pkg/pillar/cas/containerd.go`) to:

1. Read the OCI manifest for the ContentTree reference
2. Find the layer with `org.lfedge.eci.role == "disk-additional"` annotation
3. Read the blob by its SHA256 digest from the containerd content store
4. Write to the target PERSIST file

This avoids any changes to edge-containers while reusing the blob data that was
already downloaded and verified.

### Updated A/B Flow

```
1. Controller sends BaseOsConfig (single content_tree_uuid, same as today)
2. baseosmgr requests download/verify via volumemgr+verifier
   (all OCI layers — including disk-additional — stored in containerd CAS)
3. baseosmgr selects inactive Core slot (IMGA/IMGB)
4. WriteToPartition extracts disk-root → inactive partition (unchanged)
5. NEW: WriteExtensionToPersist reads disk-additional blob from CAS
   → writes to /persist/ext-imga.img or /persist/ext-imgb.img
   Target file is determined by zboot.GetOtherPartition():
   IMGA → ext-imga.img, IMGB → ext-imgb.img
   No-op if OCI manifest has no disk-additional layer (monolithic image)
6. Mark slot updating, reboot
```

### Forward Upgrade: Monolithic → Split (Self-Healing CAS Extraction)

When upgrading from a monolithic EVE version (pre-split) to a split-rootfs version,
the old `WriteToPartition` code does not know about `disk-additional` layers. The
edge-containers `FilesTarget` has an empty handler for `RoleAdditionalDisk` (line 191
in `target.go`) — the layer is silently skipped, no error. However, all OCI layers
are already stored in containerd CAS (`/persist/vault/containerd`), including the
Extension layer that was not extracted.

After reboot into the new Core, extsloader detects this situation and self-heals:

```
1. extsloader checks for Extension at /persist/ext-{imga,imgb}.img
   (paired with current partition via zboot.GetCurrentPartition())
2. File missing, but /etc/ext-verity-roothash exists → Extension IS expected
3. extsloader reads the BaseOS ContentTree reference from baseosmgr pubsub
4. Extracts disk-additional blob from local CAS by digest
   (the blob is guaranteed to be present — it belongs to the active ContentTree
   which baseosmgr never deletes; CAS lives on /persist, survives reboot)
5. Writes blob to /persist/ext-{imga,imgb}.img
   (file name derived from zboot.GetCurrentPartition(), NOT hardcoded)
6. Proceeds with normal dm-verity verify + mount
```

This eliminates the need for an intermediate "split-aware monolithic" release.
The upgrade path is: monolithic → split in a single step. The only requirement is
that the OCI image containing both layers is properly built and published.

CAS blob retention is guaranteed because:
- The ContentTree is referenced by the **active** BaseOS config
- baseosmgr has no post-activation cleanup logic for ContentTree
- volumemgr only deletes blobs when RefCount reaches 0 (requires explicit
  ContentTree deletion by controller)
- containerd CAS lives on `/persist/vault/containerd`, survives reboot

### Post-Reboot Contract

```
1. GRUB measures Core (PCR13)
2. extsloader finds Extension (or self-heals from CAS if missing)
3. extsloader verifies+mounts Extension via dm-verity
4. extsloader extends PCR12 and emits readiness
5. vaultmgr unseal path executes after readiness/terminal state
6. nodeagent testing window evaluates full device health (Core + Extension)
```

If Extension cannot load or PCR12 path is terminal-failed, device stays reachable in
degraded mode and update should fail testing window -> rollback to prior slot.

### Update Success Criteria for Split-Rootfs

> **Status: NOT YET IMPLEMENTED** — the current testing window in nodeagent does not
> check Extension state. This section defines the target behavior.

Today, nodeagent marks an update as successful (transitions from `testing` to `active`)
when the device can connect to the controller and attestation completes. For split-rootfs,
this is insufficient: an update that boots Core successfully but fails to load Extension
leaves the device without debug access, logging, monitoring, and workload networking
(wwan, guacd, etc.).

**Proposed success criteria:**

An update to a split-rootfs image should only be marked successful when:

1. **Core boots and connects to controller** — same as today
2. **Extension image is available** — `/persist/ext-{slot}.img` exists (either written
   during OTA by baseosmgr, or extracted from CAS by extsloader self-heal)
3. **Extension mounts successfully** — dm-verity verification passes and the erofs
   filesystem is mounted at the expected mount point

Individual Extension **services** failing to start should NOT block update success.
The rationale: service failures can be transient (OOM, config issue) and are recoverable
without rollback. But a missing or unmountable Extension image is a structural failure
that will persist across reboots and requires rollback to restore device functionality.

**Current testing window mechanism (code-level):**

Today, nodeagent marks an update successful purely based on time:

1. Device boots into new partition (state: `inprogress`)
2. nodeagent starts a timer when controller connectivity is established
   (`pkg/pillar/cmd/nodeagent/handletimers.go:setTestStartTime()`)
3. After `timer.test.baseimage.update` seconds (default 600s / 10 min), if the device
   hasn't rebooted, nodeagent calls `initiateBaseOsControllerTestComplete()`
   (`handletimers.go:checkUpgradeValidationTestTimeExpiry()`)
4. This sets `ZbootConfig.TestComplete = true` via pubsub
5. baseosmgr receives this, calls `zboot.MarkCurrentPartitionStateActive()` — update
   committed (`handlebaseos.go:handleZbootTestComplete()`)

"Device survived" means: **no watchdog-monitored agent process died, and no agent
stopped touching its `/run/<agent>.touch` file for 300 seconds, during the testing
window.** The watchdog daemon (`pkg/watchdog/`) monitors touch files and PIDs. A stale
touch file (300s) or dead PID triggers immediate hardware watchdog reboot. If this
reboot happens during the testing window, the previous partition becomes active again
(rollback).

There is no health check for services, no Extension check, no attestation requirement
in the testing window decision.

**Implementation approach for Extension check:**

extsloader must publish its status via pubsub (the standard EVE inter-agent
communication mechanism). The current `/run/extsloader-state.json` file is a
temporary debug aid and must be replaced — no other agent uses file-based state
sharing.

Required changes:

1. **New type `types.ExtsloaderStatus`** with fields: State (ready/failed/starting),
   Reason, Partition, ImagePath, MountPoint. Follows the same pattern as
   `types.BaseOsStatus`, `types.ZbootStatus`, etc.

2. **extsloader publishes** `ExtsloaderStatus` via `pubsub.Publish()` on every state
   transition (starting, failed, ready). Remove `writeStateFile()` and the JSON file.

3. **nodeagent subscribes** to `ExtsloaderStatus` from extsloader. In
   `handletimers.go:checkUpgradeValidationTestTimeExpiry()`, before marking
   TestComplete, check:
   ```
   if /etc/ext-verity-roothash exists (Core expects Extension):
       if ExtsloaderStatus.State != "ready":
           do NOT mark TestComplete yet (keep waiting)
           if total testing time exceeds max timeout:
               trigger reboot → rollback
   ```

4. **Testing window timing**: The existing 10-minute default should be sufficient.
   CAS extraction takes ~30-60s, dm-verity mount ~5s, service startup ~10-20s.
   Extension should be ready within ~2 minutes of boot. The remaining 8 minutes
   provide ample margin. No need to increase the testing window.

5. **Eden tests**: Switch from `eden eve ssh 'cat /run/extsloader-state.json'` to
   checking via pubsub-derived info fields or `eden eve ssh` commands that verify
   the mount point and services directly.

**What this means for rollback:**

- Corrupted Extension image → dm-verity fails → extsloader publishes `failed` →
  nodeagent holds TestComplete → testing window expires → reboot → rollback
- Missing Extension + CAS extraction fails → same path → rollback
- Extension mounts but individual service crashes → extsloader publishes `ready` →
  nodeagent marks TestComplete → update succeeds → no rollback (service issue, not
  structural failure)
- Monolithic image (no roothash) → Extension check skipped → normal testing

### CAS Self-Healing: Implementation Details

The CAS self-heal path uses the same `edge-containers` `Puller.Pull()` mechanism as
`WriteToPartition`. The OCI image config labels (`org.lfedge.eci.artifact.disk-0`)
route the Extension file from the tar layers to an output writer, via `FilesTarget`
with `Disks[0]` set to the target file. This is deterministic: the CAS reference is
resolved from pubsub (BaseOsStatus → ContentTreeStatus → ReferenceID), and the label
path uniquely identifies the Extension file within the image.

The flow in extsloader:
1. Check `/etc/ext-verity-roothash` exists (Core expects Extension)
2. Subscribe to `BaseOsStatus` (from baseosmgr) and `ContentTreeStatus` (from volumemgr)
   via pubsub — **both subscriptions must have ProcessChange in the select loop** or
   GetAll() returns empty
3. Find BaseOsStatus where PartitionLabel matches current partition
4. Look up ContentTreeStatus by ContentTreeUUID → get ReferenceID (CAS image ref)
5. Call `Puller.Pull()` with `FilesTarget{Disks: []io.Writer{file}}` — the config label
   `org.lfedge.eci.artifact.disk-0` routes the Extension file from the OCI layers
6. Verify extracted file size > 0 (empty = monolithic image, no Extension label)
7. Atomic rename `.tmp` → final path

### Rollback and Extension Rehydrate Fallback

Rollback is still GPT-native for Core (`gptprio` on IMGA/IMGB). Extension rollback is
file-native on PERSIST and therefore less robust than dedicated A/B partitions.

Rollback policy for Extension:
1. On rollback boot, first use the Extension file paired with the rolled-back Core slot
   (`ext-imga.img` or `ext-imgb.img`) using normal file-based A/B logic.
   The file name is always derived from `zboot.GetCurrentPartition()`.
2. Only if that paired file is missing/corrupt or fails verification/load, attempt
   CAS extraction (same self-healing path as forward upgrade).
3. If CAS extraction also fails, enter degraded but controller-reachable mode and
   trigger re-download.
4. Rewrite the failed slot Extension file from the downloaded artifact and retry load.

### Rollback: Split → Monolithic

When rolling back from a split-rootfs version to a pre-split monolithic version:
- Old monolithic rootfs has all services baked in — Extension is not needed.
- extsloader does not exist in the old code — no Extension loading attempted.
- PCR12 returns to all-zeros (no extsloader to extend it).
- Vault recovery handles the PCR12 change via the existing controller-based
  key escrow mechanism (same path used for any PCR13 change during update).
- Orphaned `/persist/ext-img{a,b}.img` files remain on PERSIST but are harmless
  (old code ignores them; cleaned up on next split-rootfs deployment).

### baseosmgr Delta

| Change | Description |
|--------|-------------|
| WriteToPartition extension | After writing `artifact.Root` to partition, write `artifact.Disks[0]` to paired PERSIST file |
| A/B file pairing | Target file derived from `zboot.GetOtherPartition()`: IMGA→ext-imga.img, IMGB→ext-imgb.img |
| Testing window criteria | Require Extension health (extsloader readiness state) for successful activation |
| No API change | Same `content_tree_uuid`, same ContentTree, same download/verify flow |

## 9. ZFlash Integration

ZFlash prepares USB installer media. It does not execute installation logic itself.

### Universal Image Prototype Status

Implemented on `feature/split-rootfs` branch (see Section 15 for full details):
1. `HV=uni` build variant produces a single `-uni-` image with all HV payloads
2. GRUB shows KVM/Kubevirt menu at install time (60s timeout → KVM default)
3. Installer writes selected HV to CONFIG; subsequent boots use CONFIG value
4. baseosmgr accepts `-uni-` OTA updates on both kvm and k devices

### Split Rootfs Impact

ZFlash does not place Extension on target disk; installer does that. Split-rootfs impact
is limited to UX/validation around installer payload completeness.

| Change | Description | Effort |
|--------|-------------|--------|
| Extension presence indicator | Show if source `.raw` includes Extension artifact | 0.25 SP |
| Payload validation | Validate split image completeness before flashing | 0.25 SP |

**Total ZFlash effort: 0.5 SP**

### Re-estimation Basis (Code-Grounded)

Estimate assumptions are tied to existing code:

- `tpmmgr` quote path already includes PCR 0-15.
- `DefaultDiskKeySealingPCRs` already includes PCR12.
- `zedagent` attestation path already carries TPM event log payload.
- `evetpm.copyMeasurementLog()` provides concrete integration pattern for extra log context.
- `vaultmgr` already supports controller-provided `VaultKeyPolicyPCR`.
- `device-steps.sh` currently starts `extsloader` and `vaultmgr` asynchronously, so
  policy-coupled mode requires explicit ordering/handshake work.

## 10. Effort Estimate (Selected Design)

Calibration reference: USB boot priority feature = **8 SP** total.

### Development Workstreams

| Workstream | Scope | SP |
|------------|-------|----|
| Generic Core image | Runtime guards, build-tag removal, HV runtime selection plumbing | 2 |
| Extension loader | dm-verity mount path, service lifecycle, degraded mode, CAS self-heal for forward upgrade | 3.5 |
| PCR12 measurement path | PCR12 extend states + attestation log context wiring | 1 |
| Sealing coupling + ordering | deterministic extend/unseal contract + race-safe validation | 1 |
| Installer changes | Extension artifact copy during install | 0.5 |
| baseosmgr upgrade changes | WriteToPartition disk-additional extraction, A/B file pairing, testing window | 1.5 |
| ZFlash updates | split payload validation/indicator | 0.5 |
| Build system | erofs image tooling, dm-verity root hash generation, build ordering | 2 |
| Kernel module deferred loading PoC | udev-based deferred probe validation, module split boundary definition | 1 |
| Documentation | operator and rollout docs | 0.5 |
| **Development subtotal** | | **13.5** |

Ordering/coupling extra is not zero even with PCR12 default, because deterministic boot
ordering and race-safe validation are still required to avoid recovery-loop behavior.

### Testing Tiers

| Tier | Scope | SP |
|------|-------|----|
| Docs only | Detailed manual test-case docs for verification team | 3 |
| Minimal Eden + docs | Smoke Eden automation + full docs | 5.5 |
| Full Eden | Full install/upgrade/rollback/degraded/race automation | 19 |

### Totals (Device + Controller)

| Total Type | Docs only | Minimal Eden + docs | Full Eden |
|------------|-----------|---------------------|-----------|
| Device total | ~16.5 SP | ~19 SP | ~32.5 SP |
| Controller raw | ~1 SP | ~1 SP | ~1 SP |
| Controller effective (x2) | ~2 SP | ~2 SP | ~2 SP |
| Grand total | ~18.5 SP | ~21 SP | ~34.5 SP |

Controller multiplier reflects external-team scheduling/coordination uncertainty.

## 11. Controller-Side Dependencies (Selected Design)

Controller scope for this design is intentionally minimal and informational only.
No new controller-side security controls are planned.

### Must-Have

| Change | Why | When |
|--------|-----|------|
| Extension health telemetry | Show Extension `running/failed/missing/degraded` state | Before production rollout |
| Recovery-state visibility | Make recovery/degraded reasons visible to operators | Before production rollout |

Assumption used for estimates: existing controller update/attestation flows stay as-is.
Device-side ordering/race handling remains a device implementation concern.

### Nice-to-Have

| Change | Why |
|--------|-----|
| Split update progress detail | Better visibility of Core vs Extension write state |

## 12. Delivery Plan (Selected Design)

Target architecture is fixed: Extension measured into PCR12, PCR12 included in sealing
policy, Extension stored on PERSIST as A/B files.

### Scope

- Generic Core unification
- Split rootfs mechanics (build, OCI multi-layer packaging, installer, extsloader with CAS self-heal, baseosmgr pairing)
- PCR12 measurement and attestation visibility
- Deterministic extend-before-unseal behavior with ordering/race validation
- Controller informational updates: Extension health telemetry and recovery-state visibility
- Kernel module deferred loading PoC for Extension module boundary
- End-to-end install/upgrade/rollback/degraded validation

### Total Effort

- **Device**: ~16.5 SP (docs only) / ~19 SP (minimal Eden + docs) / ~32.5 SP (full Eden)
- **Controller effective**: ~2 SP

### Prerequisites and Dependency Gates

| Gate | What must be ready | Unlocks |
|------|--------------------|---------|
| Gfw | Deferred driver loading PoC validates candidate modules for Extension | Final Extension Image content definition, build system module split |
| G1 | Extension artifact contract is stable (A/B file names, build outputs, expected runtime paths) | Final extsloader integration, baseosmgr pairing logic |
| G2 | extsloader can verify+mount real Extension image and expose deterministic success/failure states | Final PCR12 extend placement, ordering/race validation |
| G3 | Deterministic readiness handshake between extsloader and vaultmgr is defined | Fail-closed unseal behavior validation |
| G4 | Upgrade path writes inactive-slot Extension file (including CAS self-heal for monolithic→split) and rollback uses paired file first | End-to-end upgrade/rollback validation |

Important dependency note: PCR and ordering work are tightly coupled to real Extension
image lifecycle behavior. Final PCR12 placement and ordering validation are blocked until G2.

### Parallel Work Split

| Track | Main Work | Start Condition |
|-------|-----------|-----------------|
| Device Track A | Generic Core runtime guards + universal behavior | Start immediately |
| Device Track B | Split mechanics + extsloader + installer + baseosmgr pairing + PCR12 integration + ordering/race validation | Start immediately, then execute internal sequence G1 -> G2 -> G3 -> G4 |
| Controller Track X | Extension health telemetry + recovery-state visibility | Start once status/API contract from Device Track B is defined |
| Integration Gate | End-to-end install/upgrade/rollback/race checks | Start after Device Track A + Device Track B + G4 |

### Why This Split

- **General Core stays a dedicated track** because it has real uncertainty and can hit
  unpredictable blockers (for example, fragile runtime behavior around Kubevirt/KVM
  compatibility). Running it in parallel prevents that risk from stalling split-rootfs work.
- **PCR does not get a dedicated track** because only a small slice is truly independent
  (roughly ~0.5 SP: helper/plumbing). The rest depends on real extsloader lifecycle states
  and ordering handshake (G2/G3). A separate PCR track would add sync overhead and usually
  not save meaningful calendar time.

Expected schedule effect (with at least two active device contributors):
- Main acceleration comes from running Track A and Track B in parallel.
- Primary benefit is risk isolation: unexpected Generic Core issues do not stall
  split-rootfs delivery work on Track B.
- Realistic elapsed-time gain is still modest: about **~1.25-1.5 SP**.

### Parallel Investigation: Kernel Module Deferred Loading

The udev-based deferred driver loading PoC (Avi's initiative) runs in parallel with
both device tracks. Results inform the module split boundary for the Extension build
(impacts Build system workstream and Gate Gfw). This investigation should complete
before the Extension Image content is finalized.

### Delivery Timeline (Conceptual)

```
T0: Device Track A + Device Track B start in parallel
T1: Device Track B progresses through G1 -> G2 -> G3 -> G4
T2: Integration gate (requires Track A + Track B + G4)
T3: Rollout gate
```

## 13. Code Anchors

Key files referenced in this document:

### TPM and Security

| File | Purpose |
|------|---------|
| `pkg/pillar/evetpm/tpm.go:120-135` | Default sealing PCR set |
| `pkg/pillar/evetpm/tpm.go:171` | Attestation quote PCR list |
| `pkg/pillar/evetpm/tpm.go:478-514` | PCR policy validation |
| `pkg/pillar/cmd/tpmmgr/tpmmgr.go:302-360` | Attestation quote generation |
| `pkg/pillar/cmd/zedagent/attesttask.go:252-272` | PCR value encoding for attestation |
| `pkg/pillar/cmd/vaultmgr/vaultmgr.go:434-460` | Controller PCR policy handling |
| `pkg/pillar/types/verifiertypes.go:14` | Verifier scope note: SHA checksum only |
| `pkg/pillar/cmd/verifier/lib/verifier.go:42-66` | SHA256 computation and comparison |

### GRUB and Measurement

| File | Purpose |
|------|---------|
| `pkg/grub/rootfs.cfg:125` | `measurefs $root --pcr 13` |
| `pkg/grub/patches-2.06/0011-Add-measurefs-command.patch` | measurefs implementation |
| `pkg/measure-config/src/measurefs.go:23-32` | PCR 14 config measurement |

### Boot and Installation

| File | Purpose |
|------|---------|
| `pkg/installer/install` | Main installer script |
| `pkg/mkimage-raw-efi/make-raw` | Partition layout creation |
| `pkg/grub/rootfs.cfg` | 2nd-stage GRUB (boot logic) |
| `pkg/grub/embedded.cfg` | 1st-stage GRUB (minimal) |
| `pkg/eve/installer/ipxe.efi.cfg` | iPXE network boot config |
| `tools/makenet.sh` | iPXE/network installer preparation |

### Update Mechanism and OCI Content Tree

| File | Purpose |
|------|---------|
| `pkg/pillar/cmd/baseosmgr/handlebaseos.go` | Update orchestration |
| `pkg/pillar/cmd/baseosmgr/handlebaseos.go:190-194` | Re-download/overwrite rationale for suspected bad image on other slot |
| `pkg/pillar/cmd/baseosmgr/worker.go` | Partition write worker (`WriteToPartition` call site) |
| `pkg/pillar/zboot/zboot.go` | Partition state machine, `WriteToPartition` using edge-containers |
| `pkg/pillar/cmd/nodeagent/handletimers.go` | Testing window management |
| `pkg/eve/Dockerfile.in` | OCI image assembly with ECI artifact role labels |
| `vendor/.../edge-containers/pkg/registry/roles.go` | `RoleRootDisk`, `RoleAdditionalDisk` constants |
| `vendor/.../edge-containers/pkg/registry/pull.go` | `Artifact{Root, Disks[]}` extraction from OCI layers |
| `vendor/.../edge-containers/pkg/registry/target.go:191` | `RoleAdditionalDisk` empty handler (skip on old code) |
| `vendor/.../edge-containers/pkg/registry/annotations.go` | `org.lfedge.eci.artifact.disk-%d` annotation pattern |
| `pkg/pillar/cas/containerd.go` | CAS blob ingestion, lease-based GC protection |
| `pkg/pillar/cmd/volumemgr/blob.go` | Blob RefCount management, GC (only on explicit delete) |

### Split Rootfs (POC)

| File | Purpose |
|------|---------|
| `pkg/pillar/cmd/extsloader/external-services-loader.go` | Extension Loader agent |
| `images/rootfs_core.yml.in` | Core rootfs Linuxkit template |
| `images/rootfs_ext.yml.in` | Extension rootfs Linuxkit template |
| `images/rootfs_universal.yml.in` | Universal rootfs template |
| `pkg/eve/installer/grub_installer.cfg` | GRUB installer overlay (HV selection menu) |

### Generic Core Image

| File | Purpose |
|------|---------|
| `pkg/pillar/base/kubevirt.go` | `IsHVTypeKube()` runtime detection |
| `pkg/pillar/kubeapi/runtimeguard.go` | Runtime guard function |
| `pkg/pillar/hypervisor/hypervisor.go` | HV runtime selection |
| `pkg/pillar/scripts/device-steps.sh` | Conditional agent startup |
| `pkg/storage-init/storage-init.sh` | HV-aware storage init |

### Build System

| File | Purpose |
|------|---------|
| `Makefile` | Build targets for split rootfs |
| `tools/compose-image-yml.sh` | Linuxkit YAML template rendering |
| `tools/makerootfs.sh` | Rootfs image creation |
| `images/installer.yml.in` | Installer image recipe |

## 14. Memory Usage Analysis and THP Fix

### Problem: Zedbox RSS Inflation

During split-rootfs verification, zedbox RSS was observed at 250–267MB instead of the
expected 100–120MB baseline. The Go heap (measured via pprof `inuse_space`) was only
31–62MB, yet anonymous RSS reached 177MB. The discrepancy was traced to **Transparent
Huge Pages (THP)** inflating the Go runtime's heap arena.

### Root Cause: THP + Go 1.24 Arena Layout

The EVE kernel has `CONFIG_TRANSPARENT_HUGEPAGE=y` with the default policy set to
`always`. Go 1.24 maps a single large contiguous heap arena (512MB virtual range at
`0xc000000000`). With THP in `always` mode, the kernel's `khugepaged` daemon
automatically promotes 4KB pages within this range into 2MB huge pages.

The problem: Go's garbage collector allocates and frees objects across the arena,
leaving sparse live objects scattered across 2MB-aligned ranges. Each huge page
containing even one live 4KB sub-page cannot be reclaimed. The result:

- **Go heap in-use**: 31–62MB
- **Actual anonymous RSS**: 177MB (137MB trapped in huge pages)
- The slow RSS growth visible in `memory_usage.csv` is `khugepaged` scanning and
  promoting pages over 5–10 minutes after boot

This was not observed with the previous Go 1.21 + kernel 6.1 combination because
Go 1.21 used a more fragmented heap layout (less THP-friendly) and kernel 6.1 had
less aggressive `khugepaged` promotion.

### Fix: THP Policy = madvise

Setting `transparent_hugepage=madvise` on the kernel command line restricts huge page
promotion to memory regions that explicitly request it via `madvise(MADV_HUGEPAGE)`.
Go does not call this by default, so the heap arena uses standard 4KB pages.

QEMU/KVM already calls `madvise(MADV_HUGEPAGE)` for guest memory, so VM performance
is unaffected. This is the default policy on most modern distributions (RHEL, Ubuntu
22.04+, Fedora).

**Current implementation** (dev builds): added to `conf/grub.cfg` via `dom0_extra_args`:

```
set_global dom0_extra_args "$dom0_extra_args console=ttyS1,115200 transparent_hugepage=madvise"
```

**Upstream fix**: change `CONFIG_TRANSPARENT_HUGEPAGE_MADVISE=y` in the eve-kernel
defconfig (`arch/x86/configs/eve-core_defconfig`).

**Note**: editing `pkg/grub/rootfs.cfg` has no effect — grub is a pre-built OCI package.
Kernel cmdline parameters must go through `conf/grub.cfg` (`dom0_extra_args`) or the
linuxkit YAML `cmdline` field.

### Results (app running, 32 min uptime, stabilized)

| Metric | THP=always | THP=madvise | Savings |
|--------|-----------|-------------|---------|
| Total RSS | 267MB | 187MB | 80MB |
| RssAnon | 177MB | 97MB | 80MB |
| RssFile | 90MB | 90MB | 0 (binary pages) |
| Go heap THP | 137MB | 0MB | 137MB |

With THP=madvise, zedbox anonymous RSS (97MB with app running) falls within the
original 100–120MB baseline. The `PROC_ZEDBOX_THRESHOLD_MB=200` memory-monitor
threshold now has adequate headroom.

### Memory Breakdown (zedbox, 143MB binary)

| Component | RSS | Type |
|-----------|-----|------|
| Go heap + runtime | ~97MB | Anonymous (4KB pages with madvise) |
| `.text` (code) | ~37MB | File-backed (demand-paged from binary) |
| `.rodata` (constants) | ~44MB | File-backed (demand-paged from binary) |
| Other (.data, stacks, libs) | ~9MB | Mixed |

The 90MB file-backed RSS is the zedbox binary (143MB on disk, ~60% resident after
warmup). This is proportional to binary size and unavoidable — the pages are clean
and reclaimable under memory pressure.

### Cgroup Memory During Extension Mount

The extsloader temporarily raises the pillar cgroup limit by 2× the extension image
size during dm-verity mount (erofs decompression pulls blocks into page cache). After
mount, `dropImagePageCache()` uses `fadvise(FADV_DONTNEED)` to reclaim these pages,
and the cgroup limit is restored before starting extension services.

### Diagnostic Commands

```bash
# THP policy
cat /sys/kernel/mm/transparent_hugepage/enabled

# Zedbox RSS breakdown
eve exec pillar cat /proc/$(pidof zedbox)/status | grep -E 'VmRSS|RssAnon|RssFile'

# THP in Go heap arena
eve exec pillar cat /proc/$(pidof zedbox)/smaps | grep -B1 AnonHugePages | grep -v '0 kB'

# Go heap actual usage
go tool pprof -top -inuse_space heap_pillar.out

# Go runtime memstats (requires debug server enabled)
eve exec pillar curl -s 'http://localhost:6543/debug/pprof/heap?debug=1' | tail -20

# Memory-monitor CSV (tracks heap and RSS over time)
cat /persist/memory-monitor/output/memory_usage.csv
```

## 15. Universal Image (`HV=uni`)

### Overview

A universal EVE image (`-uni-` variant) ships all hypervisor payloads in a single
installer/OTA artifact. The user (or automation) selects KVM or Kubevirt at install
time. After installation, the device behaves identically to a dedicated per-HV image.

The universal image is additive: existing `-kvm-` and `-k-` pipelines are unchanged.

### Size Impact

The Extension image already includes kube services (filtered at runtime by extsloader).
The Core image already uses `PILLAR_K_TAG`. Adding kube to a KVM build increases the
Extension by ~165MB (350MB vs 185MB), which is acceptable for a single combined image.

### Implementation Status (2026-03-20)

**Implemented and QEMU-tested:**

| File | Change |
|------|--------|
| `Makefile` | Added `uni` to `HV_SUPPORTED`, auto-sets `UNIVERSAL=1` when `HV=uni`, added `eve-uni` convenience target |
| `pkg/grub/rootfs.cfg` | Added `set_uni_boot` function (marks `_eve_uni=true`, sets 60s timeout, delegates to `set_kvm_boot`). When `_eve_uni` is true, two boot menu entries are shown instead of one |
| `pkg/eve/installer/grub_installer.cfg` | Conditional `eve_flavor` — skips hardcoding `kvm` when rootfs says `uni`, so `set_uni_boot` can run |
| `pkg/installer/install` | Reads `eve_install_hv=kvm\|k` from kernel cmdline (passed by GRUB menu selection), writes chosen HV to CONFIG |
| `pkg/pillar/cmd/baseosmgr/handlebaseos.go` | Accepts `-uni-` version strings on OTA update regardless of current HV type (bypasses kvm/k mismatch rejection) |

### Build and Test

```bash
# Build
make HV=uni eve-split installer-raw    # or: make eve-uni

# QEMU smoke test (installer)
make HV=uni run-installer-raw
# GRUB shows: "Boot/Install EVE (KVM) [default]" / "Boot/Install EVE (Kubevirt / EVE-k)"
# 60s timeout, defaults to KVM
# Installer writes selected HV to CONFIG

# Check version string
cat dist/amd64/*/installer/eve_version   # contains "-uni-"

# Go vet
cd pkg/pillar && go vet -tags kubevirt ./cmd/baseosmgr/...
```

### Boot Flow

```
FRESH INSTALL (direct-dd / USB, universal image):
  USB GRUB → /etc/eve-hv-type = "uni"
  grub_installer.cfg → detects "uni", does NOT hardcode eve_flavor
  set_eve_flavor → reads "uni" from rootfs
  set_uni_boot → _eve_uni=true, timeout=60, KVM defaults
  GRUB menu → user picks KVM or Kubevirt (60s timeout → KVM)
  Selected entry adds eve_install_hv=kvm|k to kernel cmdline
  Installer reads cmdline → writes "kvm" or "k" to target CONFIG
  First real boot → GRUB reads CONFIG → normal per-HV boot

FRESH INSTALL (ZFlash, universal image):
  ZFlash → user picks HV → writes to CONFIG on USB media
  Installer → reads CONFIG → "kvm" or "k" → no menu needed
  Normal from here

OTA UPDATE (universal image to existing device):
  Device CONFIG already has "kvm" or "k" (from original install)
  baseosmgr sees "-uni-" → accepts update (bypasses HV mismatch check)
  After reboot → GRUB reads CONFIG → same HV as before → normal
  /etc/eve-hv-type = "uni" in new rootfs → never consulted (CONFIG wins)
```

### Known Issues / TODO

- **Substring match bug (fixed)**: `grep -q "eve_install_hv=k"` matched
  `eve_install_hv=kvm`. Fixed by checking `kvm` first in the installer.
- **`installer-split.raw` HV-supported list**: line 981 in Makefile writes
  `kvm\nk\nxen\n` to CONFIG — should include `uni` if ZFlash needs to
  validate it.
- **Eden test coverage**: No automated test for the GRUB menu interaction
  (inherently interactive). OTA acceptance can be tested via existing Eden
  upgrade workflow with `EVE_HV=uni`.

## 16. Kernel Module Deferred Loading PoC (2026-03-23)

### Size Inventory (live QEMU EVE device, amd64)

Total: ~11.5MB compressed modules + ~133MB firmware = ~144MB.

| Category | Modules (KB) | Firmware (KB) | Connectivity? | Deferrable? |
|----------|-------------|---------------|---------------|-------------|
| Ethernet drivers | 2,736 | 2,631 (bnx2x) | YES — NIM primary | **No** |
| WiFi drivers + stack | 2,402 | ~129,000 | YES — WiFi uplink | Firmware only (see below) |
| WWAN/MHI | ~250 | — | YES — cellular | **No** |
| ZFS + SPL | 1,509 | — | YES on k/ZFS | **No** |
| Bluetooth | 340 | — | No | **Yes** |
| CAN | 171 | — | No | **Yes** |
| NFS/sunrpc + NFS fs | 936 | — | No | **Yes** |
| iSCSI | 86 | — | No | **Yes** |
| HID/input | 92 | — | No | **Yes** |
| IIO sensors | 118 | — | No | **Yes** |

Non-connectivity deferrable total: **~1.7MB** (modest).

WiFi firmware: **~126MB** — only loads when WiFi hardware is present. Most edge servers
have no WiFi, making this dead weight. Could move to Extension with a ~30s connectivity
delay for WiFi-only devices (rare; wired/cellular is always primary).

### Mechanism Validation (QEMU-tested, 2026-03-23)

The overlay-based deferred loading mechanism was validated end-to-end:

```
1. Mount overlay on /lib/modules/<ver>/ with Extension as additional lowerdir  → WORKS
2. depmod -a rebuilds dependency map including Extension modules               → WORKS
3. modprobe loads a module from the Extension layer (bluetooth tested)         → WORKS
4. rmmod + modprobe cycle (cfg80211) through overlay                           → WORKS
```

**Implementation pattern for extsloader:**
```bash
KVER=$(uname -r)
# After Extension image is mounted at $EXT_MOUNT:
mkdir -p /lib/modules/$KVER
mount -t overlay overlay \
  -o lowerdir=$EXT_MOUNT/lib/modules/$KVER:/hostfs/lib/modules/$KVER \
  /lib/modules/$KVER
depmod -a $KVER
udevadm trigger --action=add   # re-probe unbound devices
```

**Limitation:** `depmod` writes to `modules.dep` in the upper layer (tmpfs). This is
fine — the dependency map is ephemeral and rebuilt on every boot.

### Recommendation

1. **Phase 1 (low risk, ~1.7MB):** Move non-connectivity modules (bluetooth, CAN, NFS,
   iSCSI, HID, IIO) to Extension. Validates the pipeline end-to-end with minimal risk.

2. **Phase 2 (product decision, ~126MB):** Move WiFi firmware to Extension. Requires
   explicit acceptance of ~30s WiFi delay on WiFi-only devices. WiFi kernel modules stay
   in Core (they handle missing firmware gracefully — log warning, no crash).

3. **Not recommended:** Moving ethernet drivers, WiFi drivers, WWAN, or ZFS. These are
   all connectivity-critical or variant-essential.
