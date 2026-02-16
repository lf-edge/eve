# Split Rootfs Design Document

**Version**: 1.6
**Status**: Working design document with resolved architectural decisions and POC implementation details.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Terminology](#terminology)
3. [Problem Statement](#problem-statement)
4. [Goals and Non-Goals](#goals-and-non-goals)
5. [Background: How EVE Security Works Today](#background-how-eve-security-works-today)
6. [Background: How EVE Handles Installation and Updates](#background-how-eve-handles-installation-and-updates)
7. [Proposed Solution: Split Rootfs](#proposed-solution-split-rootfs)
8. [Impact on Operators](#impact-on-operators)
9. [Architectural Decisions](#architectural-decisions)
10. [Implementation Plan](#implementation-plan)
11. [POC Implementation Status](#poc-implementation-status)
12. [Future Extensions](#future-extensions)
13. [References](#references)

---

## Executive Summary

EVE's rootfs is approaching the 300MB partition limit. This document proposes splitting it into two images:

- **Core Image**: Minimal system for boot, controller communication, and updates (~240MB)
- **Extension Image**: Non-critical services loaded after boot (~60MB)

The split maintains EVE's security guarantees through PCR measurement and attestation, while enabling graceful degradation if the Extension Image fails to load.

---

## Terminology

Different names have been used for these concepts across PR discussions, design proposals, and code. This document standardizes on the terms below:

| Term | Also referred to as | Definition |
|------|---------------------|------------|
| **Core Image** | boot+core, bootstrap, bootstrap_rootfs | Minimal rootfs with kernel, pillar, and services essential for boot and controller communication |
| **Extension Image** | system+app, pkgs, pkgs_rootfs, extra image | Separate image containing non-critical services, loaded after boot |
| **Extension Loader** | extsloader | Pillar agent that discovers, verifies, and mounts the Extension Image |
| **TPM** | | Trusted Platform Module - security chip for measurements and key protection |
| **PCR** | | Platform Configuration Register - TPM register that records measurements |
| **Attestation** | | Process where device proves its software state to the controller |
| **Sealing** | | Encrypting data so TPM only releases it when PCRs match expected values |
| **Digest** | | SHA256 hash used to verify content integrity |

---

## Problem Statement

### The Immediate Problem

EVE's rootfs is approaching the **300MB partition limit**:

| Variant | Current Size | Limit | Headroom |
|---------|--------------|-------|----------|
| amd64-kvm-generic | ~277MB | 300MB | 23MB |
| arm64-kvm-nvidia-jp6 | ~296MB | 300MB | 4MB |

CVE fixes and new dependencies are consuming the remaining space. Users cannot receive critical security updates without partition resizing.

### Why 300MB?

The limit exists for backward compatibility. EVE 10.10.0 increased the default to 512MB for new installations, but devices in the field still have the old partition layout. Resizing requires maintenance windows that users may not schedule for urgent CVE patches.

### The Strategic Problem

EVE's monolithic design leads to many different builds for different hardware. A modular approach would allow a common base with pluggable components.

### Why Split Rootfs Solves This

Analysis shows which packages can move to a separate image:

| Variant | Packages to Move | Size Saved | Resulting Size |
|---------|------------------|------------|----------------|
| amd64-kvm-generic | eve-wwan, eve-debug, eve-vtpm | 38MB | 239MB |
| arm64-kvm-generic | eve-wwan, eve-debug, eve-vtpm | 35MB | 218MB |
| arm64-kvm-nvidia-jp5 | eve-nvidia, eve-wwan, eve-debug | 114MB | 237MB |
| arm64-kvm-nvidia-jp6 | eve-nvidia, eve-wwan, eve-debug, eve-vector, eve-vtpm, eve-edgeview, eve-guacd, eve-node-exporter | 166MB | 280MB |
| amd64-kubevirt-generic | eve-wwan, eve-kube | 112MB | 268MB |

All variants fit under 300MB after moving non-critical services to an Extension Image. Generic variants need only 35-38MB moved; specialized variants (nvidia, kubevirt) benefit more significantly.

Note: eve-wwan was decided to stay in Core (see [Architectural Decisions](#architectural-decisions)). Actual savings are ~5MB less than shown above for variants that include it.

---

## Goals and Non-Goals

### Goals

1. Create a Core Image that fits within 300MB partition limit
2. Load non-critical services from a separate Extension Image
3. Maintain EVE's security guarantees (measured boot, attestation, tamper detection)
4. Enable graceful degradation (device works if Extension Image fails)
5. Minimize changes to operator workflow

### Non-Goals (Initial Implementation)

- Changing partition sizes (parallel effort)
- Controller-side changes for managing split images
- Moving firmware/drivers out of Core Image (future phase)
- Full container-based modularity (future work)

---

## Background: How EVE Security Works Today

This section explains EVE's current security model. Understanding this is essential for evaluating the proposed changes.

### TPM and PCRs

Every EVE device has a TPM (Trusted Platform Module) that provides:
- Secure key storage (keys never leave the chip)
- Platform Configuration Registers (PCRs) for recording system state
- Cryptographic signing for attestation quotes

**PCRs are 16 independent 256-bit registers** (PCR 0 through PCR 15):

| PCR | Extended By | Contains |
|-----|-------------|----------|
| 0-7 | UEFI firmware | Firmware, bootloader, Secure Boot state |
| 4 | GRUB | Kernel hash (extends existing value) |
| 8-9 | Kernel | OS-specific measurements |
| 12 | (unused) | **Proposed: Extension Image** |
| 13 | GRUB | Rootfs partition hash |
| 14 | measure-config | EVE /config contents |

**Key properties:**

1. **Initialized to zero** - All PCRs start as `0x0000...` on power-on

2. **Extend-only operation** - You cannot write arbitrary values. You can only extend:
   ```
   PCR[n]_new = SHA256(PCR[n]_current || measurement)
   ```

3. **Irreversible** - Cannot undo an extend. Only reboot resets PCRs.

4. **Independent** - Each PCR is a separate register. Extending PCR 4 does not affect PCR 14.

**Example: PCR evolution during EVE boot**

At power-on, all PCRs are zero:
```
PCR 0  = 0x0000...
PCR 4  = 0x0000...
PCR 14 = 0x0000...
```

UEFI extends PCR 0 with firmware hash:
```
PCR 0  = SHA256(0x0000... || firmware_hash) = 0xAAAA...      ← extended
PCR 4  = 0x0000...
PCR 14 = 0x0000...
```

UEFI extends PCR 4 with bootloader hash:
```
PCR 0  = 0xAAAA...
PCR 4  = SHA256(0x0000... || bootloader_hash) = 0xBBBB...    ← extended (1st time)
PCR 14 = 0x0000...
```

GRUB extends PCR 4 again with kernel hash (same PCR, second extend):
```
PCR 0  = 0xAAAA...
PCR 4  = SHA256(0xBBBB... || kernel_hash) = 0xCCCC...        ← extended (2nd time)
PCR 14 = 0x0000...
```

GRUB extends PCR 4 again with initrd hash (same PCR, third extend):
```
PCR 0  = 0xAAAA...
PCR 4  = SHA256(0xCCCC... || initrd_hash) = 0xDDDD...        ← extended (3rd time)
PCR 14 = 0x0000...
```

EVE's measure-config extends PCR 14 with /config hash:
```
PCR 0  = 0xAAAA...
PCR 4  = 0xDDDD...
PCR 14 = SHA256(0x0000... || config_hash) = 0xEEEE...        ← extended
```

**Key insights:**

1. **Multiple extends accumulate**: PCR 4 was extended three times. Its final value (0xDDDD...) represents the entire chain: bootloader → kernel → initrd. Changing any component in the chain produces a different final value.

2. **PCRs are independent**: PCR 14 was extended directly from zero. It is not affected by PCR 0 or PCR 4. If you update the kernel (changing PCR 4), PCR 14 remains the same because /config didn't change.

### Measured Boot

The PCR example above illustrates the measured boot chain: UEFI → GRUB → kernel → EVE services, each extending PCRs before passing control. If any component is modified, the corresponding PCR value changes, which breaks sealing and is detected by attestation.

### Attestation: How Controller Verifies Device State

EVE regularly proves to the controller what software is running:

```
┌─────────────────┐                         ┌─────────────────┐
│    Zedcloud     │                         │   EVE Device    │
│   (Controller)  │                         │                 │
└────────┬────────┘                         └────────┬────────┘
         │                                                    │
         │  1. "Prove your state (nonce: 0xRANDOM)"           │
         │ ─────────────────────────────────────────►         │
         │                                                    │
         │         2. TPM signs all 16 PCR values + nonce
         │                                           │
         │  3. "Here's my signed quote"              │
         │ ◄─────────────────────────────────────────│
         │                                           │
         │  4. Controller validates:                 │
         │     • Signature from real TPM? ✓          │
         │     • Nonce fresh (not replay)? ✓         │
         │     • PCR values match baseline? ✓        │
         │                                           │
```

**What controller learns:**
- PCR 0-7: Firmware and bootloader correct?
- PCR 8-9: Kernel correct?
- PCR 14: Configuration correct?

### Sealing: Protecting Disk Encryption Keys

EVE seals the disk encryption key to specific PCR values:

```
Seal (first boot):
  "TPM, encrypt this disk key. Only decrypt if PCRs match these values."

Unseal (every boot):
  TPM checks: Do current PCRs match sealed policy?
    • Yes → Release disk key → Disk decrypts → Boot continues
    • No  → Refuse → Disk stays encrypted → Boot fails
```

**EVE's sealing PCRs:** `{0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14}`

If an attacker modifies the bootloader, PCR 4 changes, unsealing fails, and the disk stays encrypted.

### PCR Baseline Management: Operator Workflow

The controller uses **"trust on first use with operator approval"**:

**1. New Device (First Boot)**
```
Device boots → sends PCR values → Controller: "No baseline for this device"

Operator sees in UI:
┌─────────────────────────────────────────────────────┐
│ Device: edge-device-042                             │
│ Status: Attestation - NEEDS APPROVAL                │
│                                                     │
│ PCR Values:                                         │
│   PCR 0:  0xABCD1234... (UEFI firmware)             │
│   PCR 4:  0x5678EFAB... (bootloader/kernel)         │
│   PCR 14: 0x9999CCCC... (/config)                   │
│                                                     │
│ [Accept as Baseline]  [Reject Device]               │
└─────────────────────────────────────────────────────┘

Operator clicks "Accept" → Controller stores baseline
```

**2. Normal Operation**
```
Device boots → PCRs match baseline → Attestation passes automatically
Operator sees: "Attestation: Passed ✓"
```

**3. PCR Values Change**
```
Device boots → PCRs different from baseline → Controller flags mismatch

Operator sees in UI:
┌─────────────────────────────────────────────────────┐
│ Device: edge-device-042                             │
│ Status: Attestation - FAILED                        │
│                                                     │
│ Changed PCRs:                                       │
│   PCR 4:  0x5678EFAB... → 0xNEWVALUE...             │
│           (bootloader/kernel changed)               │
│                                                     │
│ [Accept New Baseline]  [Quarantine Device]          │
└─────────────────────────────────────────────────────┘

Operator decides:
  • Expected (EVE update): Accept new baseline
  • Unexpected (tampering): Quarantine and investigate
```

### EVE Update: How PCR Changes Are Handled

When EVE is updated, PCR values change. The system uses a **two-party key escrow** mechanism to handle this:

```
1. NORMAL OPERATION (before update)
   Disk key sealed to current PCRs (e.g., PCR 4 = 0xAAAA)
   Encrypted backup copy of disk key stored on controller
   (controller cannot read it - encrypted by TPM, not sealed to PCRs)

2. UPDATE INSTALLED, DEVICE REBOOTS
   New kernel → PCR 4 = 0xBBBB
   TPM won't unseal disk key (PCR 4 doesn't match sealed policy)
   Device cannot access disk

3. AUTOMATIC RECOVERY
   Device connects to controller and re-attests with new PCR values
   Controller checks its policy:
     ├─► PCRs match known EVE version profile?
     │   YES → Automatic: send encrypted backup key, no operator needed
     │
     └─► PCRs don't match any known profile?
         NO → Flag for operator review (possible tampering)

4. DEVICE COMPLETES BOOT
   Device decrypts backup key using TPM
   Device re-seals disk key to new PCR values
   Device continues boot normally

5. OPERATOR ACCEPTS NEW BASELINE
   Controller flags PCR change in UI
   Operator reviews and accepts new baseline
   (For expected updates this is routine confirmation)
```

**Key distinction:** The disk key recovery is automatic for recognized updates. The operator baseline acceptance is a separate step - it updates the attestation baseline so future boots pass without flagging. If the controller doesn't recognize the PCR values, recovery is blocked until the operator approves.

---

## Background: How EVE Handles Installation and Updates

This section explains EVE's disk layout, installation flow, and A/B update mechanism. Understanding this is essential for deciding where the Extension Image should be placed on disk.

### Disk Partition Layout

EVE uses a GPT partition table with static UUIDs. The installer (`pkg/mkimage-raw-efi/make-raw`) creates the following layout:

```
┌──────────────────────────────────────────────────────────────────────────┐
│ MBR (sector 0): GRUB stage1 bootblock (446 bytes)        [NOT UPDATED]   │
├──────────────────────────────────────────────────────────────────────────┤
│ GRUB stage2 embedded in gap (sectors 34-2048, ~1MB)      [NOT UPDATED]   │
├──────────────────────────────────────────────────────────────────────────┤
│ Part 1 — EFI System (36MB, FAT32)                        [NOT UPDATED]   │
│   1st stage GRUB: minimal, chainloads to IMGA/IMGB                       │
│   EFI/BOOT/BOOTX64.EFI + grub.cfg (~6 lines)                             │
│   Only job: gptprio.next → select partition → chainload                  │
├──────────────────────────────────────────────────────────────────────────┤
│ Part 2 — IMGA (≥512MB, squashfs rootfs)                  [UPDATED]       │
│   2nd stage GRUB: full boot logic, measurefs, HW detection               │
│   kernel, pillar, all services                                           │
├──────────────────────────────────────────────────────────────────────────┤
│ Part 3 — IMGB (≥512MB, squashfs rootfs)                  [UPDATED]       │
│   Same layout as IMGA; A/B update target                                 │
├──────────────────────────────────────────────────────────────────────────┤
│ Part 4 — CONFIG (1MB, FAT12)                             [NOT UPDATED]   │
│   device.cert.pem, server URL, soft_serial, onboarding certs             │
│   eve-hv-type (optional: HV override set by ZFlash at flash time)        │
│   eve-hv-supported (optional: lists supported HV types for ZFlash)       │
├──────────────────────────────────────────────────────────────────────────┤
│ Part 9 — P3 / PERSIST (remaining space, ext4 or ZFS)     [READ-WRITE]    │
│   /persist: volumes, logs, status, vault, certs, agentdebug              │
└──────────────────────────────────────────────────────────────────────────┘
```

**`[NOT UPDATED]`** — written once at installation, never modified by OS updates.
**`[UPDATED]`** — replaced entirely on each OS update by `baseosmgr`.
**`[READ-WRITE]`** — persistent mutable storage, survives updates and reboots.

**Key properties:**
- Partition sizes and UUIDs are hard-coded in `pkg/mkimage-raw-efi/make-raw`
- IMGA/IMGB are identically sized and contain complete squashfs rootfs images
- Hybrid MBR/GPT allows booting on UEFI, legacy BIOS, and ARM boards
- The PERSIST partition (P3) takes all remaining disk space

**Two-stage GRUB design:**

EVE uses a two-stage GRUB architecture to keep the non-updatable bootloader minimal:

| | 1st Stage (EFI partition) | 2nd Stage (inside IMGA/IMGB) |
|---|---|---|
| **Config** | `embedded.cfg` (~6 lines, rescue shell syntax) | `rootfs.cfg` (~586 lines, full GRUB scripting) |
| **Written** | Once at installation | Every OS update |
| **Updatable** | No — the only component that cannot be upgraded after deployment | Yes — ships with each rootfs |
| **Responsibility** | `gptprio.next` → select partition → chainload | Detect HW, `measurefs` PCR 13, load kernel |
| **TPM measurement** | None | `measurefs $root --pcr 13` |

The 1st stage is intentionally kept as simple as possible because it is the only component in the EVE stack that cannot be upgraded after deployment. All boot logic, TPM measurement, and hardware detection live in the 2nd stage, which is updated with every EVE release.

**Note on IMGC:** The partition table also supports a Part 7 (IMGC) used only on evaluation platform images. Evaluation images are special pre-install images used to verify hardware compatibility before committing to a full EVE deployment. IMGC is not relevant to the split rootfs design and is not discussed further.

### Installation Flow

The installer (`pkg/installer/install`) is a self-contained bootable image that runs on a device and writes EVE to permanent storage:

```
┌─────────────────────────────────────────────────────────────────┐
│                    INSTALLATION FLOW                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Boot installer from USB/media                               │
│     └─ TUI (Rust) or automated via kernel cmdline params        │
│                                                                 │
│  2. Probe for destination disk                                  │
│     └─ eve_install_disk= from kernel cmdline or user selection  │
│                                                                 │
│  3. Create partition table (make-raw)                           │
│     └─ GPT with EFI, IMGA, IMGB, CONFIG, P3                     │
│     └─ Write 1st stage GRUB (MBR + EFI) — never updated again   │
│                                                                 │
│  4. Write rootfs.img → IMGA partition (dd)                      │
│     └─ Squashfs image copied directly to raw partition          │
│     └─ IMGB left empty (populated on first update)              │
│                                                                 │
│  5. Initialize PERSIST (ext4 or ZFS)                            │
│     └─ ZFS supports multi-disk RAID (mirror, raidz1, raidz2)    │
│                                                                 │
│  6. Write CONFIG partition                                      │
│     └─ Generate device certificates (TPM-backed if available)   │
│     └─ Store server URL and onboarding data                     │
│                                                                 │
│  7. Mark IMGA as bootable (GPT priority attributes)             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Key detail:** The rootfs.img is written directly to the raw IMGA partition via `dd`. There is no filesystem on IMGA — the squashfs image IS the partition content. This means any additional images (like an Extension Image) cannot simply be placed "inside" the IMGA partition alongside the rootfs.

### How Kernel and Rootfs Coexist in the Squashfs

The IMGA/IMGB partition IS the squashfs image — there is no filesystem layer on top.
The squashfs contains everything in a flat structure:

```
squashfs (the entire IMGA or IMGB partition content)
├── boot/
│   ├── kernel          ← Linux kernel binary
│   ├── cmdline         ← "rootdelay=3 ..." (from Linuxkit YAML)
│   ├── xen.gz          ← Xen hypervisor (xen builds only)
│   └── ucode.img       ← CPU microcode (x86)
├── EFI/BOOT/
│   ├── BOOTX64.EFI     ← 2nd-stage GRUB binary
│   └── grub.cfg        ← 2nd-stage GRUB config (rootfs.cfg)
├── containers/
│   ├── onboot/         ← Onboot container images (storage-init, etc.)
│   └── services/       ← Service container images (pillar, etc.)
├── sbin/, bin/, etc/   ← Root filesystem (from Linuxkit init containers)
└── ...
```

**Key insight: GRUB reads files directly from squashfs.** GRUB has a built-in `squash4`
filesystem module (compiled into both 1st and 2nd stage GRUB). This lets GRUB read
`/boot/kernel`, `/EFI/BOOT/grub.cfg`, etc. directly from the squashfs partition —
no loopback mount or intermediate filesystem needed.

**For normal disk boot, there is NO initrd.** The `$initrd` variable in `rootfs.cfg`
is only set by `grub_installer.cfg` for installer/ISO/iPXE boot. For normal operation,
GRUB loads the kernel and passes `root=PARTUUID=<squashfs-partition>` — the kernel then
mounts the squashfs directly as a read-only root filesystem.

This means **squashfs must be compiled into the kernel** (`CONFIG_SQUASHFS=y`, not `=m`).
Without an initrd, there is no opportunity to load a kernel module before mounting root.

**The host root is read-only squashfs — no overlayfs at host level.** Linuxkit's init
binary (`/init`) checks if root is tmpfs/ramfs and only performs filesystem gymnastics in
that case. For squashfs root, it directly execs `/sbin/init`. Services like pillar run
inside containerd containers, which have their own overlayfs rootfs. Inside a container,
`/hostfs` is a bind mount of the host's actual squashfs:

```
Host:      /        = squashfs (read-only, from IMGA/IMGB partition)
           /persist = ext4 or ZFS (writable, from P3 partition)

Container: /        = overlayfs (containerd snapshotter)
           /hostfs  = bind mount of host's squashfs root
           /persist = bind mount of host's /persist
```

The initrd (`pkg/mkimage-raw-efi/initramfs-init.patch`) is only used during
installer/iPXE boot. In that case it creates an overlayfs (squashfs lower + tmpfs upper)
to allow the installer to inject additional content into the root filesystem.

### Boot Sequence

```
1. Firmware (UEFI/BIOS) → loads 1st stage GRUB from EFI partition
2. 1st stage GRUB [NOT UPDATED — written once at install]:
   └─ gptprio.next selects highest-priority partition (IMGA or IMGB)
   └─ Chainloads 2nd stage GRUB from squashfs: /EFI/BOOT/BOOTX64.EFI
3. 2nd stage GRUB [UPDATED — inside IMGA or IMGB squashfs]:
   └─ Detects architecture, hypervisor, platform
   └─ measurefs $root --pcr 13 (measures rootfs into TPM)
   └─ Reads /boot/cmdline from squashfs for kernel cmdline
   └─ Loads /boot/kernel from squashfs via linux command
   └─ Passes root=PARTUUID=<squashfs-partition> to kernel (NO initrd)
4. Kernel mounts squashfs partition directly as read-only root
5. Linuxkit init → containerd → onboot containers
6. storage-init detects and mounts CONFIG → /config, P3 → /persist
7. Pillar agents start (zedagent, nim, domainmgr, baseosmgr, ...)
```

### A/B Update Mechanism

EVE uses IMGA and IMGB for atomic, rollback-safe OS updates. The flow is orchestrated by three cooperating agents: `baseosmgr`, `nodeagent`, and `volumemgr`.

#### Update Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    UPDATE FLOW                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Controller sends BaseOsConfig to zedagent                   │
│     └─ Contains: version, ContentTreeUUID, Activate=true        │
│                                                                 │
│  2. baseosmgr receives config                                   │
│     └─ Requests volumemgr to download + verify image            │
│                                                                 │
│  3. volumemgr downloads image to Content Addressable Storage    │
│     └─ Verifies SHA256, transitions to LOADED state             │
│                                                                 │
│  4. baseosmgr assigns target partition                          │
│     └─ If booted from IMGA → target is IMGB (and vice versa)    │
│     └─ Target must be in "unused" state                         │
│                                                                 │
│  5. Worker thread writes image to target partition              │
│     └─ zboot.WriteToPartition() via edge-containers library     │
│     └─ Extracts from containerd CAS → writes to raw device      │
│                                                                 │
│  6. baseosmgr marks target partition "updating"                 │
│     └─ Sets GPT priority attributes for next boot               │
│                                                                 │
│  7. Device reboots into new partition                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Post-Reboot Validation (Testing Window)

After rebooting into the new partition, it enters a **testing window** before being marked active:

```
┌─────────────────────────────────────────────────────────────────┐
│                    TESTING WINDOW                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. New partition boots in "inprogress" state                   │
│                                                                 │
│  2. nodeagent monitors system health                            │
│     └─ Tries to reach controller                                │
│     └─ Configurable test period                                 │
│                                                                 │
│  3. SUCCESS: controller reachable, system healthy               │
│     └─ nodeagent publishes ZbootConfig(TestComplete=true)       │
│     └─ baseosmgr marks new partition "active"                   │
│     └─ Old partition marked "unused"                            │
│                                                                 │
│  4. FAILURE: crash, hang, or controller unreachable             │
│     └─ Next reboot → gptprio falls back to old partition        │
│     └─ Old partition ("active") boots successfully              │
│     └─ Failed partition stays "inprogress" → effectively dead   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Partition State Machine

```
        ┌──────────┐  write image   ┌──────────┐
        │  unused  │ ──────────────►│ updating │
        └──────────┘                └──────────┘
              ▲                                │
              │                     reboot
              │                          │
              │                          ▼
    mark old  │                    ┌────────────┐
    partition │                    │ inprogress │
              │                    └────────────┘
              │                          │
              │               test passes│
              │                          ▼
        ┌──────────┐               ┌──────────┐
        │  unused  │ ◄──────────── │  active  │
        └──────────┘  (old part.)  └──────────┘
```

#### Key Properties of the Update System

| Property | Detail |
|----------|--------|
| Update unit | Single rootfs.img (squashfs) written to raw partition |
| Write method | `zboot.WriteToPartition()` — extracts from containerd CAS to block device |
| What gets updated | IMGA or IMGB only (includes 2nd stage GRUB, kernel, all services) |
| What does NOT update | EFI partition (1st stage GRUB), CONFIG, MBR/BIOS bootloader |
| Partition selection | baseosmgr picks whichever of IMGA/IMGB is "unused" |
| Atomicity | Old partition untouched until new one passes tests |
| Rollback | Automatic via GRUB gptprio if new partition fails to boot |
| Forced fallback | Controller can send `ForceFallbackCounter` to roll back |
| Image source | Downloaded via volumemgr → stored in containerd CAS on PERSIST |

#### Where Downloaded Images Live Before Installation

During an update, the new rootfs.img is:
1. **Downloaded** by volumemgr to `/persist/` (containerd's Content Addressable Storage)
2. **Verified** (SHA256 checksum)
3. **Written** from CAS directly to the target IMGA/IMGB raw partition
4. **Removed** from CAS after successful installation

The PERSIST partition acts as temporary staging for update images.

### Extension Image Placement Analysis

The disk layout and update flow create specific constraints for where the Extension Image can live. This section analyzes all considered options and explains the rationale for the chosen approach.

#### Option 1: Embedded Inside Rootfs Squashfs

Place Extension services inside the same squashfs image as Core.

**Rejected.** This defeats the entire purpose — the rootfs size would still include Extension content, and the 300MB partition limit would remain a problem.

#### Option 2: Appended After Rootfs in IMGA/IMGB

Write both core.squashfs and extension.img sequentially to the same IMGA/IMGB partition, using the squashfs superblock's `total_size` field to find where Core ends and Extension begins.

```
IMGA partition (512MB or 300MB):
┌──────────────────────────┬───────────────────┬─────────┐
│ Core squashfs (~240MB)   │ Extension (~60MB) │ unused  │
│ ← measured by PCR 13 →  │ NOT in PCR 13     │          │
└──────────────────────────┴───────────────────┴─────────┘
```

**Rejected.** Two problems:

1. **Does not fit on old devices.** Pre-10.2.0 devices (before June 2023) have 300MB IMGA/IMGB partitions. Core (~240MB) + Extension (~60MB) = 300MB — no headroom. New installations since 10.2.0 have 512MB partitions, but we must support existing devices.

2. **GRUB `measurefs` does not cover appended data.** EVE's GRUB `measurefs` command reads the squashfs superblock's `total_size` and hashes only that many bytes. Any data appended after the squashfs boundary is NOT included in the PCR 13 measurement. Extension would need a separate measurement mechanism regardless.

#### Option 3: New EXTA/EXTB Partitions

Add dedicated partitions for Extension Image, mirroring the IMGA/IMGB A/B scheme.

```
Disk: [EFI][IMGA][IMGB][EXTA][EXTB][CONFIG][P3...]
```

**Not chosen for Phase 1.** While this provides the cleanest security model (GRUB can `measurefs` into PCR 12, same trust level as Core), it has practical issues:

- **Requires partition layout changes** to `make-raw`, `storage-init`, installer, and GRUB config.
- **Existing ext4 devices** need P3 (PERSIST) shrunk via `resize2fs` + `sgdisk` to free space. Feasible but adds a migration step.
- **Existing ZFS devices cannot shrink P3.** ZFS pools do not support shrinking. These devices would need a fallback mechanism.
- **Scope.** The partition layout change is a significant effort that spans the entire boot and update chain. Decoupling it from the initial split rootfs work reduces risk.

This remains a viable option for a future phase (see [Future: GRUB-Based Extension Measurement](#measuring-extension-image-from-grub)).

#### Option 4: On PERSIST Partition (Chosen)

Store the Extension Image as a file on the PERSIST partition, with A/B copies managed by `baseosmgr`.

**Chosen.** This approach works for both installation and updates with no partition layout changes. The security analysis below explains how integrity is maintained despite PERSIST being a read-write partition.

**How PERSIST encryption works (and why it matters):**

Only `/persist/vault/` is encrypted (via fscrypt on ext4 or native ZFS encryption). Everything else on `/persist/` — including the Extension Image — is **plaintext**. The encryption key for vault is sealed to TPM PCRs and released only when the correct software is running.

The PERSIST partition is mounted early by `storage-init.sh`, **before** vault unsealing and before most pillar agents start. This means Extension Loader can access the Extension Image early in the boot process, without waiting for TPM/vault operations.

**Placement within PERSIST — two sub-options:**

**A) Plaintext on PERSIST root (`/persist/ext-imga.img`, `/persist/ext-imgb.img`)**

```
Boot ordering:
  storage-init mounts /persist     ← Extension Image accessible HERE
      ↓
  extsloader verifies + mounts     ← runs immediately, no vault dependency
      ↓
  vaultmgr unseals vault           ← happens in parallel, not a blocker
```

- Extension services start early (before vault unlock)
- No dependency on TPM/vault for Extension loading
- Digest verification catches any tampering at boot

**B) Inside vault (`/persist/vault/ext-imga.img`, `/persist/vault/ext-imgb.img`)**

```
Boot ordering:
  storage-init mounts /persist     ← vault/ encrypted, Extension NOT accessible
      ↓
  vaultmgr unseals vault           ← must complete first
      ↓
  extsloader verifies + mounts     ← can only run AFTER vault unlock
```

- Extension services start later (after vault unlock)
- Adds offline tamper protection: an attacker who boots from USB cannot read or modify the Extension Image (encrypted by TPM-sealed key)
- Prevents offline DoS attack: attacker cannot delete/corrupt Extension Image to force degraded mode
- **Trade-off during updates:** when PCRs change after an OS update, the vault cannot be unsealed until the controller provides the backup key. During this window, Extension Image is inaccessible. However, Core services (including controller communication) run independently of vault, so recovery proceeds normally.

**Decision: Vault placement (option B) is preferred** for its offline DoS prevention properties. The later startup is acceptable because Extension services are non-critical by design. The update-time vault recovery works because Core services handle controller communication independently.

**A/B naming convention on PERSIST:**

```
/persist/vault/ext-imga.img  ← Extension for when IMGA is active
/persist/vault/ext-imgb.img  ← Extension for when IMGB is active
```

Extension Loader determines which file to load based on the currently active partition (from `zboot.GetCurrentPartition()`). During updates, `baseosmgr` writes the new Extension Image to the file corresponding to the inactive partition, alongside writing the new Core to the inactive IMGA/IMGB.

**Security on a read-write partition:**

The Extension Image lives on a writable filesystem. This is addressed by multiple layers:

| Attack | Without vault | With vault |
|--------|--------------|------------|
| Offline attacker replaces Extension | Modified file fails digest → degraded mode (DoS only) | Cannot access encrypted directory |
| Offline attacker deletes Extension | Missing file → degraded mode (DoS only) | Cannot access encrypted directory |
| Runtime attacker replaces Extension | Caught on next boot by digest; current boot unaffected (already mounted read-only) | Same (vault is unlocked at runtime) |

The digest verification (SHA256 embedded in Core Image, which is measured into PCR 13) ensures that a tampered Extension Image is **never loaded**. The attacker cannot run malicious code via a modified Extension — they can only cause a denial of service (degraded mode). Vault placement prevents even that DoS for offline attackers.

Runtime integrity (detecting tampering of the Extension file while the system is running) is provided by erofs + dm-verity — see [Image Format](#2-image-format).

**Summary: Why PERSIST over alternatives**

| Requirement | PERSIST (vault) | IMGA/IMGB append | EXTA/EXTB |
|-------------|----------------|-------------------|-----------|
| Works on old 300MB devices | Yes | No (too tight) | Needs migration |
| Works on ZFS devices | Yes | N/A | No (can't shrink) |
| No partition layout changes | Yes | Yes | No |
| A/B rollback | Via naming convention | Free | Free |
| Offline tamper protection | Yes (vault encrypted) | No (raw partition) | Possible (GRUB measure) |
| GRUB-level measurement | No (userspace PCR 12) | No | Yes |
| Same path for install + update | Yes | Yes | Yes |

---

## Proposed Solution: Split Rootfs

### Architecture Overview

Split the monolithic rootfs into two images:

```
┌─────────────────────────────────────────────────────────────────┐
│                         TODAY                                   │
├─────────────────────────────────────────────────────────────────┤
│  rootfs.img (squashfs, ~280MB)                                  │
│  ├── kernel, init, pillar                                       │
│  ├── eve-wwan, eve-debug, eve-vtpm                              │
│  ├── memory-monitor, edgeview, guacd   ← non-critical           │
│  └── ... everything in one image                                │
└─────────────────────────────────────────────────────────────────┘

                              ▼

┌─────────────────────────────────────────────────────────────────┐
│                        PROPOSED                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Core Image (squashfs, ~240MB)     Extension Image (~60MB)      │
│  ┌─────────────────────────────┐   ┌─────────────────────────┐  │
│  │ kernel, init                │   │ eve-debug               │  │
│  │ pillar (nim, zedagent, etc) │   │ eve-vtpm                │  │
│  │ containerd                  │   │ memory-monitor          │  │
│  │ networking (wlan,wwan,dns)  │   │ edgeview                │  │
│  │ Extension Loader            │   │ guacd                   │  │
│  └─────────────────────────────┘   │ node-exporter           │  │
│            │                       └─────────────────────────┘  │
│            │ loads & verifies               ▲                   │
│            └────────────────────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Boot Flow

```
1. UEFI loads GRUB                    (measured into PCRs 0-7)
2. GRUB loads kernel                  (measured into PCR 4)
3. Kernel mounts Core Image           (already measured into PCR 13 by GRUB)
4. storage-init mounts /persist       (plaintext accessible; vault still locked)
5. Core services start (pillar, nim, zedagent, vaultmgr, extsloader)
6. vaultmgr unseals /persist/vault/   (TPM releases key based on PCRs)
7. Extension Loader runs (after vault unlock):
   a. Determine active partition (IMGA or IMGB)
   b. Find Extension Image at /persist/vault/ext-{active}.img
   c. Read dm-verity root hash from /hostfs/etc/ext-verity-roothash
   d. Set up loop device + dm-verity (veritysetup)
   e. Measure Extension Image into PCR 12          ← NEW
   f. Mount verified erofs read-only
   g. Start services via containerd
8. Attestation sends all PCRs (including PCR 12) to controller
```

### Security Model

**Chain of Trust:**
```
Hardware TPM (root of trust)
  └─► Measures boot chain → PCRs 0-9
      └─► GRUB measures Core squashfs → PCR 13
          └─► Core squashfs contains /etc/ext-verity-roothash
              └─► Extension Loader sets up dm-verity with trusted root hash
                  └─► Every block read from Extension erofs is verified
                      └─► Extension Loader measures into PCR 12
                          └─► Attestation reports all PCRs
                              └─► Controller validates state
```

**Security Properties:**

| Property | How It's Achieved |
|----------|-------------------|
| Core Image integrity | TPM measured boot + PCR sealing (as today) |
| Extension Image integrity | dm-verity (root hash in Core, verified per-block) + PCR 12 measurement |
| Runtime tamper detection | dm-verity returns I/O error on any modified block |
| Tamper detection (controller) | Controller sees PCR 12 in attestation |
| Graceful degradation | PCR 12 not in sealing set (device boots without Extension) |

**Why PCR 12?**

| PCR | In Sealing Set? | In Attestation? | Current Use |
|-----|-----------------|-----------------|-------------|
| 0-9, 13-14 | Yes | Yes | Boot chain, config |
| **12** | **No** | **Yes** | **Unused → Extension Image** |

- Not in sealing: Extension Image failure won't brick device
- In attestation: Controller can verify Extension Image integrity

### Security Limitations

Extension Loader runs in userspace as part of Pillar, which is part of the Core Image. This creates a conditional trust chain:

- Core Image integrity is guaranteed by the measured boot chain (GRUB measures rootfs into PCR 13, PCR 13 is in the sealing set)
- Therefore: if Core Image is intact, Extension Loader is trustworthy, the dm-verity root hash is authentic, and PCR 12 measurement is trustworthy
- Extension Image integrity depends on Core Image integrity (the dm-verity root hash lives in Core)
- If Core Image is compromised, Extension measurements cannot be trusted regardless of PCR 12 value

A future enhancement could measure the Extension Image from GRUB directly (see [Future: GRUB-Based Extension Measurement](#measuring-extension-image-from-grub)), which would make it equivalent to Core Image measurement.

### PCR 12 Sentinel Measurement

Instead of leaving PCR 12 at zero on failure, Extension Loader uses multi-step measurement to distinguish failure modes:

```
Boot starts:        PCR 12 = 0x0000...  (Extension Loader hasn't run yet)

Extension Loader starts:
  PCR 12 = extend(0, "extsloader:starting")

Image found and verified:
  PCR 12 = extend(prev, SHA256(extension.img))

Services started:
  PCR 12 = extend(prev, "extsloader:services-running")

OR on failure:
  PCR 12 = extend(prev, "extsloader:failed:<reason>")
```

This lets the controller distinguish:
- PCR 12 = zero: Extension Loader never ran (Core compromise or early boot failure)
- PCR 12 = non-zero, no image hash: Extension Image not found or failed verification
- PCR 12 = full chain: Extension loaded successfully

### Integrity Verification (dm-verity)

The Extension Loader verifies the Extension Image using dm-verity before mounting:

```
┌─────────────────────────────────────────────────────────────────┐
│                    EXTENSION LOADER FLOW                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Read trusted dm-verity root hash from                       │
│     /hostfs/etc/ext-verity-roothash                             │
│     (embedded in Core squashfs at build time,                   │
│      Core squashfs measured into PCR 13 by GRUB)                │
│                                                                 │
│  2. Find Extension Image at /persist/vault/ext-{active}.img     │
│                                                                 │
│  3. Set up loop device on the Extension Image file              │
│                                                                 │
│  4. Set up dm-verity: veritysetup open loop-dev ext-verified    │
│     --root-hash <trusted-hash>                                  │
│     ├─► Success: dm-verity device /dev/mapper/ext-verified      │
│     └─► Failure: root hash mismatch → run degraded              │
│                                                                 │
│  5. Measure Extension Image into PCR 12                         │
│                                                                 │
│  6. Mount /dev/mapper/ext-verified as erofs (read-only)         │
│     (every subsequent block read verified by dm-verity)         │
│                                                                 │
│  7. Start services via containerd                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Extension Image Lifecycle

#### Image Locations

The Extension Image exists in different locations depending on the lifecycle stage:

| Location | Purpose | Example Path |
|----------|---------|-------------|
| **Discover** | Where Extension Loader first finds the image | Partition written by installer; IMGB partition after update |
| **Staging** | Temporary location while preparing for use | (may not be needed if discover = load) |
| **Load** | Where the image is actually mounted and used | The partition device (e.g., same as discover) |

**Key requirement:** Integrity MUST be verified at the Load location (not just at discover). The digest check and PCR 12 measurement happen on the image that is actually mounted.

#### Workflows by Use Case

**First Installation:**
```
1. Installer writes Core Image to IMGA partition (same as today's rootfs)
2. Installer initializes PERSIST partition (ext4 or ZFS)
3. vaultmgr creates /persist/vault/ on first boot
4. Installer (or first-boot script) writes Extension Image to /persist/vault/ext-imga.img
   → extension.img is included in the installer media at /bits/extension.img
5. Extension Loader waits for vault unlock
6. Sets up dm-verity (root hash from Core squashfs) → measures PCR 12 → mounts erofs → starts services
```

**Regular Boot (after installation):**
```
1. GRUB boots Core Image from active partition (e.g., IMGA)
2. storage-init mounts /persist
3. Core services start (pillar, nim, zedagent, vaultmgr)
4. vaultmgr unseals vault (TPM releases key because PCRs match)
5. Extension Loader discovers /persist/vault/ext-imga.img
6. Sets up dm-verity (root hash from Core) → measures PCR 12 → mounts erofs read-only → starts services
7. Core + Extension operate as one system
```

**System Update (Core + Extension):**
```
1. Controller pushes new EVE version (Core + Extension bundled)
2. baseosmgr downloads and verifies the bundle via volumemgr (same as today)
3. baseosmgr writes new Core Image to inactive partition (IMGB if IMGA is active)
4. baseosmgr writes new Extension Image to /persist/vault/ext-imgb.img
5. Device reboots into IMGB
6. vaultmgr recovers vault key (PCRs changed → controller provides backup key)
7. Extension Loader sets up dm-verity for /persist/vault/ext-imgb.img (root hash from new Core) → measures → mounts erofs
8. Testing window (same as current baseosmgr flow)
9. On success: mark IMGB active; old /persist/vault/ext-imga.img preserved for rollback
10. On failure: reboot into IMGA; old Core + old /persist/vault/ext-imga.img load normally
```

Note: Core and Extension are always the same version. There are no Extension-only updates.

#### A/B Mechanism for Extension Image

Core + Extension are logically one unit. The A/B mechanism for Extension uses file naming on PERSIST:

```
/persist/vault/ext-imga.img  ← Extension for IMGA (partition A)
/persist/vault/ext-imgb.img  ← Extension for IMGB (partition B)
```

- Extension Loader reads `zboot.GetCurrentPartition()` to determine which file to load
- `baseosmgr` writes the new Extension to the file matching the inactive partition
- Rollback to old partition means the old Extension file is loaded (unchanged on PERSIST)
- Both files are preserved across updates; `baseosmgr` only overwrites the inactive one
- Vault encryption protects both files from offline tampering

### OCI Spec Best Practices for Extension Services

Extension services are defined by OCI specs (`config.json`) embedded in the Extension Image. Since the Extension Image is built by the same build system and verified by digest, the OCI specs are trusted.

Best practices for Extension service OCI specs:
- Run as non-root where possible
- Use read-only rootfs (overlayfs lower layer from verified image)
- Limit capabilities to the minimum required
- Use separate PID namespaces
- Follow the same security patterns as existing linuxkit service containers

### Graceful Degradation

If Extension Image fails (missing, corrupted, tampered), the device enters degraded mode.

**Degraded mode = controller connectivity only, no workloads.**

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEGRADED MODE                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  RUNNING (minimal Core services):                               │
│    • nim, zedagent (controller communication)                   │
│    • baseosmgr (receive updates/rollback commands)              │
│    • networking (wlan, wwan, dnsmasq)                           │
│                                                                 │
│  NOT RUNNING:                                                   │
│    • Workload VMs and containers — NOT started                  │
│    • Extension services (memory-monitor, edgeview, debug, etc)  │
│                                                                 │
│  Purpose: Device stays reachable so operator can:               │
│    • Push a new EVE update (with working Extension Image)       │
│    • Trigger a rollback to previous known-good version          │
│    • Diagnose the failure via controller-side telemetry         │
│                                                                 │
│  Controller status: "Device operational, Extension failed,      │
│                      workloads suspended"                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Degraded Mode Threat Analysis

| Scenario | Impact | Mitigation |
|----------|--------|------------|
| Attacker corrupts Extension Image to disable monitoring | Monitoring (memory-monitor, node-exporter) unavailable; attacker activity harder to detect | Controller sees PCR 12 mismatch or sentinel value indicating failure |
| Attacker corrupts Extension to prevent VM start | Workloads don't run (denial of service) | Operator pushes update or rollback via controller |
| eve-debug unavailable in degraded mode | Debug shell inaccessible | Actually a security benefit — reduces attack surface |
| eve-vtpm unavailable | VMs that depend on vTPM cannot start | Covered by "no workloads in degraded mode" policy |

### Threat Model

| Threat | Mitigated? | How |
|--------|-----------|-----|
| Extension Image tampered on disk | Yes | dm-verity root hash (embedded in Core Image) won't match → setup fails |
| Extension Image replaced with older version | Yes | Old version's dm-verity root hash won't match current Core's embedded hash |
| Core + Extension rollback attack | Yes | Same A/B + testing mechanism as current rootfs prevents rollback |
| Attacker forces degraded mode (corrupts Extension) | Partially | Controller detects via PCR 12; device stays reachable; no workloads run |
| Offline attacker corrupts/deletes Extension (DoS) | Yes | Vault encryption prevents access without TPM-sealed key |
| Offline attacker replaces Extension with malicious image | Yes | Vault encryption + digest verification (even without vault, digest catches it) |
| Runtime attacker replaces Extension file on PERSIST | Yes | dm-verity returns I/O error on any tampered block read; current mount is protected at block level |
| Compromised Core loads bad Extension | No (by design) | Extension trust depends on Core integrity, which is guaranteed by boot chain |
| Malicious OCI spec in Extension container | Mitigated | Extension Image is built by the same build system and verified by digest; spec is embedded in the verified image |
| Extension service resource exhaustion | No (not applicable) | After loading, Core + Extension operate as one system; same resource model as today |

### Current POC Gap

The current POC (`pkg/pillar/cmd/extsloader/`) does NOT implement the full security model:

| Feature | Design | POC Status |
|---------|--------|------------|
| Find Extension Image | ✓ | ✓ Implemented |
| Set up dm-verity | Required | ✗ Missing |
| Mount erofs | Required | ✗ Missing (uses squashfs) |
| Measure into PCR 12 | Required | ✗ Missing |
| Start services | ✓ | ✓ Implemented |
| Universal HV selection | ✓ | ✓ Implemented (CONFIG-based) |
| Installer support | ✓ | ✓ Implemented (`installer-split` target) |
| ZFlash HV selection UI | ✓ | ✓ Implemented |

**Before production, Extension Loader must be updated to use dm-verity/erofs and measure PCR 12.**

See [POC Implementation Status](#poc-implementation-status) for details on what has been implemented.

---

## Impact on Operators

### What Stays the Same

| Aspect | Change? |
|--------|---------|
| Device onboarding process | No change |
| Periodic attestation | No change (automatic) |
| EVE update process | No change |
| Accepting new PCR baselines | Same UI, one more PCR |

### What Changes

**1. One More PCR in Baseline**

```
Before:                              After:
┌─────────────────────────┐         ┌─────────────────────────┐
│ PCR baseline:           │         │ PCR baseline:           │
│   PCR 0-9  (boot chain) │         │   PCR 0-9  (boot chain) │
│   PCR 13   (rootfs)     │         │   PCR 12   (Extension)  │ ← NEW
│   PCR 14   (/config)    │         │   PCR 13   (rootfs)     │
│                         │         │   PCR 14   (/config)    │
└─────────────────────────┘         └─────────────────────────┘
```

**2. New Status: Extension Image Health**

Operators will see Extension Image status separately from Core:

```
Device: edge-device-042
┌─────────────────────────────────────────────────────┐
│ Core Image:      Running ✓                          │
│ Extension Image: Running ✓    (or: FAILED ✗)        │
│ Attestation:     Passed ✓                           │
└─────────────────────────────────────────────────────┘
```

**3. PCR 12 Change on EVE Update**

Core and Extension are always the same version and update together. When EVE is updated, PCR 12 changes along with other boot chain PCRs:

```
Scenario: EVE update (Core + Extension v1.0 → v1.1)

Operator sees:
┌─────────────────────────────────────────────────────┐
│ Attestation: FAILED - PCR mismatch                  │
│                                                     │
│ Changed:                                            │
│   PCR 4:  0x1234... → 0xABCD... (kernel)            │
│   PCR 12: 0xAAAA... → 0xBBBB... (Extension Image)   │
│   PCR 13: 0x5678... → 0xEFGH... (rootfs)            │
│                                                     │
│ Unchanged:                                          │
│   PCR 14: 0x9999... (config)                        │
│                                                     │
│ [Accept New Baseline]                               │
└─────────────────────────────────────────────────────┘
```

### PCR 12 is Predictable

Unlike hardware-dependent PCRs (0-7), **PCR 12 can be pre-computed**:

```
PCR 12 = SHA256(0x0000... || SHA256(extension.img))

Same extension.img → Same PCR 12 on ALL devices
```

**Proposed tool:**
```bash
$ compute-pcr12 --image extension-v1.1.img
Expected PCR 12: 0xBBBB5678...

# Operators can verify before accepting new baseline
```

### Diagnostic Tools on Device

| Tool | Command | Purpose |
|------|---------|---------|
| Read PCRs | `tpmmgr printPCRs` | Show all current PCR values |
| TPM info | `tpmmgr printCapability` | TPM hardware details |
| Measurement log | `cat /persist/status/measurefs_tpm_event_log` | What was measured |

---

## Architectural Decisions

### 1. What Goes in Core vs Extension

**Core Image (must-have for boot and controller comms):**
- pillar core (nim, zedagent, domainmgr, volumemgr, baseosmgr)
- containerd
- networking (wlan, wwan, dnsmasq)
- kernel, firmware
- Extension Loader

**Extension Image:**
- eve-debug, eve-vtpm
- memory-monitor, node-exporter
- edgeview, guacd
- eve-nvidia (GPU support)

**Decision: eve-wwan is in Core Image.** Some deployments use cellular as the only network connection. If eve-wwan were in Extension and the Extension fails, cellular-only devices lose all controller connectivity. This violates Goal #4 (graceful degradation — device must remain manageable). The size impact (~5MB) is acceptable.

### 2. Image Format

**Decision: Core Image stays squashfs. Extension Image uses erofs + dm-verity.**

The Core rootfs and Extension Image have fundamentally different boot requirements, so
they can (and should) use different image formats:

- **Core Image (squashfs)**: The entire boot chain depends on squashfs — GRUB reads files
  from it via the `squash4` module, the kernel mounts it directly as root with compiled-in
  squashfs support. Changing this would require modifications to GRUB, kernel config, and
  the boot sequence. No reason to change what works.

- **Extension Image (erofs + dm-verity)**: Only mounted at runtime by Extension Loader via
  loop device. GRUB never touches it. No boot chain dependency. Since the Extension Loader
  is new code anyway, it should be written for erofs + dm-verity from the start rather than
  implementing squashfs support first and migrating later.

#### Extension Image structure

```
extension.erofs (erofs image, with dm-verity hash tree appended)
├── containers/services/memory-monitor/
│   ├── config.json      (OCI spec)
│   └── lower/           (read-only rootfs tree)
├── containers/services/eve-debug/
│   ├── config.json
│   └── lower/
├── containers/services/eve-vtpm/
│   └── ...
└── containers/services/node-exporter/
    └── ...
```

Extension Loader sets up dm-verity on the loop device, mounts the verified erofs
filesystem read-only, then creates an overlayfs per service (lower = verified image
content, upper = writable tmpdir).

#### Why erofs + dm-verity for Extension (not squashfs)

| Property | squashfs | erofs + dm-verity |
|----------|----------|-------------------|
| Boot-time digest verification | Yes | Yes |
| PCR 12 measurement | Yes | Yes |
| **Runtime integrity** | **No** — file on PERSIST could be replaced without detection until reboot | **Yes** — every block read verified against Merkle hash tree |
| Tamper during runtime | Undetected until next boot | **I/O error on tampered blocks** |
| Compression | xz, zstd, lz4 | lz4, zstd, deflate |
| Random access | Slower (block-level decompression) | Faster (page-aligned, direct I/O) |
| Boot performance | Good | Better (designed for fast mount) |
| Maturity in EVE | Proven for Core rootfs | New for Extension (proven in Android) |

**Why this matters for PERSIST placement:** The Extension Image lives on a writable
partition. Without dm-verity, an attacker who gains runtime write access to PERSIST
could replace the extension file — the current boot is unaffected (already mounted),
but the replacement goes undetected until next boot. With dm-verity, every block read
from the mounted filesystem is verified against a Merkle hash tree. If the underlying
file is modified while mounted, any read from the affected region returns an I/O error.
This makes the writable nature of PERSIST largely irrelevant for security.

**Multi-service container support:** erofs is just a filesystem format. It supports the
same directory structure as squashfs — a single erofs image can contain multiple service
directories, each with its own `config.json` and `rootfs/` tree. The Extension Loader
reads service directories from the mount point regardless of the underlying filesystem.

**Android precedent:** Android uses erofs + dm-verity for system partitions (Android 11+),
which is the same use case — verified read-only content on potentially writable storage.
This demonstrates production readiness at scale.

#### dm-verity root hash management

dm-verity requires a trusted root hash to verify blocks against. The root hash is stored
inside the Core squashfs at `/etc/ext-verity-roothash`, embedded at build time. Since the
Core squashfs is measured into PCR 13 by GRUB, this creates a chain of trust:

```
TPM PCR 13 seals Core squashfs
  └─► Core squashfs contains /etc/ext-verity-roothash
      └─► dm-verity validates every block of Extension erofs against root hash
```

Extension Loader reads the root hash from `/hostfs/etc/ext-verity-roothash` (the host's
squashfs, bind-mounted into the container), sets up dm-verity on the loop device using
`veritysetup`, then mounts the verified erofs filesystem. If the root hash doesn't match
the Extension Image, dm-verity setup fails and the system enters degraded mode.

This approach replaces the separate SHA256 digest file (`/etc/extension.sha256`). The
dm-verity root hash serves the same purpose (integrity verification) while also providing
runtime block-level verification that a simple digest check cannot offer.

#### Prerequisites

| Requirement | Status | Effort |
|-------------|--------|--------|
| `CONFIG_EROFS_FS=y` in kernel | Missing (containerd logs: `modprobe erofs` fails) | Kernel config change in eve-kernel repo |
| `CONFIG_DM_VERITY=y` in kernel | Likely present (device-mapper used in EVE) | Verify |
| `mkfs.erofs` in build tools | Missing | `erofs-utils` Alpine package |
| `veritysetup` at runtime | Likely available via `cryptsetup` | Verify |
| dm-verity root hash in Core Image | New | Build system change |
| Containerd EROFS snapshotter | Present but skipped (missing kernel module) | Enabled by kernel config |

### 3. Delivery Mechanism

**Decision: Bundled. Core + Extension in single update package.**

Two separate files in the update package (not a single archive, not embedded):
- Core Image: rootfs.img (same as today)
- Extension Image: extension.img (new)
- Both verified by baseosmgr as part of the same update transaction
- Both written to the target partition slot (A or B)
- Version coupling: Extension Image dm-verity root hash embedded in Core Image guarantees they match

### 4. Trusted Root Hash Source

**Decision: dm-verity root hash embedded in Core Image.**

The Extension Image's dm-verity root hash is embedded in the Core Image at build time (`/etc/ext-verity-roothash`). Since the Core squashfs is measured into PCR 13 by GRUB, the root hash is transitively protected by the TPM-measured boot chain. This means Extension can only change when Core changes. This is by design: Core and Extension are parts of the same software version.

### 5. Failure Mode

**Decision: Degraded mode — controller connectivity only, no workloads.**

See [Graceful Degradation](#graceful-degradation) for detailed behavior.

### 6. Extension Image Placement

**Decision: On PERSIST partition, inside vault, with A/B naming convention.**

See [Extension Image Placement Analysis](#extension-image-placement-analysis) for the full comparison of alternatives (IMGA/IMGB append, EXTA/EXTB partitions, PERSIST plaintext, PERSIST vault).

Summary of the decision:

- **Location**: `/persist/vault/ext-imga.img` and `/persist/vault/ext-imgb.img`
- **A/B mechanism**: File naming tied to active partition; `baseosmgr` manages both files
- **Vault**: Provides offline DoS prevention (encrypted, TPM-sealed)
- **Why not IMGA/IMGB append**: Does not fit on old 300MB devices; GRUB `measurefs` only covers squashfs content
- **Why not EXTA/EXTB**: Requires partition layout changes; ZFS devices cannot shrink P3; deferred to future phase
- **Runtime integrity**: Addressed by erofs + dm-verity (see [Image Format](#2-image-format))

---

## Implementation Plan

### POC Phase (Complete)
- [x] CONFIG-based HV override (GRUB, storage-init, onboot.sh)
- [x] Core + Extension rootfs Linuxkit YAML templates
- [x] `rootfs-split`, `live-split`, `run-split` Makefile targets
- [x] Extension Loader agent (`extsloader`) — discovers and starts services from squashfs
- [x] `installer-split` Makefile target with `eve-hv-supported` metadata
- [x] Installer reads HV type from CONFIG, copies ext to persist
- [x] ZFlash: probe source image CONFIG for `eve-hv-supported`
- [x] ZFlash: HV selection popup (KVM, Kubevirt, Xen)
- [x] ZFlash: write `eve-hv-type` to CONFIG partition post-flash
- [x] ZFlash: FAT12 filesystem support in DeviceWrapperFatPartition
- [x] QEMU boot test (`make UNIVERSAL=1 run-split`)

### Phase 1: Kernel + Build System Preparation
- [ ] Enable `CONFIG_EROFS_FS=y` in EVE kernel build (eve-kernel repo)
- [ ] Verify `CONFIG_DM_VERITY=y` in EVE kernel (likely already present)
- [ ] Add `mkfs.erofs` to build tools (`erofs-utils` Alpine package)
- [ ] Verify `veritysetup` available at runtime (part of `cryptsetup`)
- [ ] Migrate Extension Image from squashfs to erofs
- [ ] Generate dm-verity hash tree for Extension Image at build time
- [ ] Embed dm-verity root hash in Core Image (`/etc/ext-verity-roothash`)
- [ ] Create bundled update format (Core squashfs + Extension erofs)

### Phase 2: Extension Loader + Integration
- [ ] Extension Loader: wait for vault unlock, load from `/persist/vault/ext-{active}.img`
- [ ] Extension Loader: A/B file selection based on `zboot.GetCurrentPartition()`
- [ ] Extension Loader: set up loop device + dm-verity (`veritysetup open`)
- [ ] Extension Loader: mount verified erofs read-only
- [ ] Add PCR 12 measurement to Extension Loader
- [ ] PCR 12 sentinel measurements (starting, loaded, failed)
- [ ] Update `baseosmgr`: write Extension Image to `/persist/vault/ext-{inactive}.img` during updates

### Phase 3: Testing
- [ ] Verify attestation includes PCR 12
- [ ] Test degraded mode (missing/corrupted Extension)
- [ ] Test update scenarios (A/B on PERSIST, vault recovery)
- [ ] Test rollback (old Core + old Extension loaded correctly)
- [ ] Test offline tamper resistance (vault prevents modification)
- [ ] Test dm-verity runtime integrity (tamper Extension file while mounted)
- [ ] Benchmark erofs + dm-verity vs. squashfs performance

### Phase 4: Integration
- [ ] Controller-side PCR 12 awareness (if needed)
- [ ] Operator documentation
- [ ] Migration guide for existing devices

---

## POC Implementation Status

The POC demonstrates the split rootfs concept end-to-end: building universal images, booting in QEMU, flashing to devices with HV selection via ZFlash.

### Universal Image Concept

A key insight driving the POC: **KVM, Xen, and Kubevirt use identical binaries**. The hypervisor type is a runtime decision, not a build-time decision. The file `/run/eve-hv-type` determines which hypervisor abstraction pillar uses (`pkg/pillar/hypervisor/hypervisor.go`). Xen packages (`xen.gz`, Xen tools) are always included in the rootfs regardless of HV type.

This means a single "universal" installer image can serve all three hypervisor modes. The HV type is selected either:
1. At **flash time** — ZFlash writes `eve-hv-type` to CONFIG partition
2. At **boot time** — GRUB reads `/config/eve-hv-type` and writes `/run/eve-hv-type`

### Part 1: CONFIG-Based HV Override

**Files changed:**

| File | Change |
|------|--------|
| `pkg/grub/rootfs.cfg` | Read `eve-hv-type` from CONFIG partition, write to `/run/eve-hv-type` |
| `pkg/pillar/cmd/onboot/onboot.sh` | Read `eve-hv-type` from CONFIG, propagate to runtime |
| `pkg/mkimage-raw-efi/storage-init.sh` | Select ext4 or ZFS for persist based on CONFIG `eve-hv-type` |

The override chain: CONFIG `eve-hv-type` → GRUB reads it → sets `$hv` → writes `/run/eve-hv-type` → pillar uses it for hypervisor dispatch.

### Part 2: Build System — Split Rootfs Targets

**Files changed:**

| File | Change |
|------|--------|
| `images/rootfs-core.yml.in` | Core rootfs Linuxkit YAML (boot-critical services only) |
| `images/rootfs-ext.yml.in` | Extension rootfs Linuxkit YAML (non-critical services) |
| `Makefile` | `rootfs-split`, `live-split`, `run-split`, `installer-split` targets |
| `pkg/pillar/cmd/extsloader/` | Extension Loader agent (new) |

**Build commands:**
```bash
make UNIVERSAL=1 rootfs-split    # Build both rootfs-core.img and rootfs-ext.img
make UNIVERSAL=1 live-split      # Build bootable QEMU image
make UNIVERSAL=1 run-split       # Boot in QEMU
make UNIVERSAL=1 installer-split # Build flashable installer image
```

The `UNIVERSAL=1` flag forces `HV=kvm` as the base (since all HV types share binaries) and activates split rootfs build logic.

### Part 3: Installer Support

**Files changed:**

| File | Change |
|------|--------|
| `images/installer.yml.in` | Add `rootfs-ext.img` bind mount and file entry |
| `pkg/installer/install` | Read HV type from CONFIG; copy rootfs-ext.img to `/persist/pkgs.img` |
| `Makefile` | `installer-split` target, `eve-hv-supported` metadata injection |

**Installer flow for split rootfs:**
1. Installer boots from USB/media (same as standard installer)
2. Reads `eve-hv-type` from CONFIG partition (set by ZFlash at flash time)
3. Creates persist filesystem (ext4 for kvm/xen, ZFS for kubevirt/k)
4. Writes rootfs-core.img to IMGA partition
5. Copies rootfs-ext.img to `/persist/pkgs.img` for extsloader

**`eve-hv-supported` metadata:**

The build system writes an `eve-hv-supported` file to the CONFIG partition listing supported HV types (one per line). This file is used by ZFlash to determine which HV options to present:

```
kvm
k
xen
```

This is injected during the `installer-split.raw` build:
```makefile
printf "kvm\nk\nxen\n" | MTOOLS_SKIP_CHECK=1 mcopy -i $(CONFIG_IMG) - ::/eve-hv-supported
```

### Part 4: ZFlash Integration

ZFlash (the EVE flashing tool) was extended to support HV type selection at flash time.

**Files changed (in zflash repo):**

| File | Change |
|------|--------|
| `src/downloadthread.h/.cpp` | `setEveCustomization()` — writes `eve-hv-type` to CONFIG partition 4 post-flash |
| `src/imagewriter.h/.cpp` | `isEveImage()`, `getEveHvSupported()`, `setEveHvType()` — EVE detection and orchestration |
| `src/main.qml` | HV selection popup (KVM, Kubevirt, Xen buttons with dynamic enable/disable) |
| `src/devicewrapperfatpartition.cpp` | FAT12 filesystem support (read/write) |

**How ZFlash detects universal EVE images:**

ZFlash does NOT use filename-based detection (to avoid false positives with old installers). Instead, it probes the source `.raw` file's CONFIG partition:

1. `isEveImage()` calls `getEveHvSupported()`
2. `getEveHvSupported()` opens the source `.raw` file as a `DeviceWrapper`
3. Reads GPT partition entry 4 (CONFIG, 1MB FAT12)
4. Attempts to read `eve-hv-supported` file from the FAT12 filesystem
5. If found → universal image; if not found → standard image (no popup)

**HV selection flow:**
```
User selects installer-split.raw → clicks Write
  → ZFlash probes CONFIG for eve-hv-supported
  → Found: shows popup with KVM / Kubevirt / Xen buttons
  → User selects HV type
  → ZFlash flashes image to target device
  → Post-flash: writes eve-hv-type to CONFIG partition 4 on target device
  → Device boots with selected HV type
```

**FAT12 support:**

EVE's CONFIG partition is 1MB, which uses FAT12 (not FAT16/FAT32). ZFlash's `DeviceWrapperFatPartition` was extended with full FAT12 read/write support:
- 12-bit packed FAT entries (1.5 bytes each, odd/even cluster handling)
- FAT12 EOF markers (>= 0xFF8)
- Cluster allocation, directory operations, and file read/write

**GPT partition layout of installer-split.raw:**

```
Entry 0: EFI System (36MB, FAT32)
Entry 1: (empty)
Entry 2: (empty)
Entry 3: CONFIG (1MB, FAT12)        ← fatPartition(4) reads this
Entry 4: (empty)
Entry 5: installer (squashfs)
Entry 6: inventory
```

Note: GPT entries are NOT sequential. `fatPartition(nr)` reads entry at index `nr-1`.

### Testing Results

| Test | Status | Notes |
|------|--------|-------|
| `make UNIVERSAL=1 live-split` + QEMU boot | Passed | extsloader loads 9 extension services (kube skipped for kvm) |
| `make UNIVERSAL=1 installer-split` build | Passed | Produces 463MB installer-split.raw |
| ZFlash: probe non-universal image | Passed | No popup shown for standard installers |
| ZFlash: probe universal image | Passed | Popup shows KVM/Kubevirt/Xen with correct enable states |
| ZFlash: flash with KVM selection | Passed | `eve-hv-type=kvm` written to CONFIG |

---

## Future Extensions

### Firmware and Drivers Outside Core

Once service split is stable, consider moving non-boot-critical drivers:

**Candidates for Extension:**
- GPU drivers (nvidia, AMD)
- Specialized network drivers
- USB device drivers

**Must stay in Core:**
- Storage drivers (NVMe, SATA)
- Basic network drivers
- TPM drivers

**Challenge:** Kernel modules must be available when hardware is detected. May need early Extension mount.

### Measuring Extension Image from GRUB

Currently (Phase 1-2), the Extension Image lives on PERSIST (inside vault) and is measured into PCR 12 by the Extension Loader in userspace. A stronger approach would be to measure it from GRUB, the same way the Core rootfs is measured into PCR 13. This requires moving the Extension Image from PERSIST to a dedicated partition.

**Prerequisites:**
- Extension Image must be on a known partition at boot time (not on `/persist`)
- Dedicated partition(s) for Extension Image (EXTA/EXTB, mirroring IMGA/IMGB)
- GRUB config updated to: `measurefs $ext_root --pcr 12`

**Benefits:**
- Extension measurement happens in the boot chain (before kernel), same trust level as Core
- Enables adding PCR 12 to the sealing set if desired
- Eliminates dependency on userspace measurement
- No longer needs vault for offline tamper protection (GRUB measurement provides stronger guarantees)

**Trade-offs:**
- Requires changes to `make-raw`, `storage-init`, installer, and GRUB config
- On existing devices, P3 (PERSIST) fills all remaining disk space — EXTA/EXTB require shrinking P3 first
  - **ext4**: feasible via `resize2fs` + `sgdisk` to adjust P3 end sector and create new partitions
  - **ZFS**: not feasible (ZFS pools cannot be easily shrunk)
- New installations: straightforward — add EXTA/EXTB before P3 in `make-raw`
- GRUB must know about the Extension partition
- Migration from PERSIST-based to partition-based placement needed

**Proposed approach:**
```
1. Add EXTA/EXTB partitions to disk layout (parallel to IMGA/IMGB)
   - New installs: make-raw creates EXTA/EXTB before P3
   - Existing ext4 devices: storage-init shrinks P3, creates EXTA/EXTB on first boot after upgrade
   - Existing ZFS devices: keep PERSIST-based approach (no partition change)
2. Update GRUB rootfs.cfg:
   - After measuring Core rootfs into PCR 13
   - Measure Extension partition into PCR 12: measurefs $ext_root --pcr 12
3. Extension Loader still mounts and starts services
   - But verification is now redundant (GRUB already measured)
   - Can optionally keep userspace digest check as defense-in-depth
4. Consider adding PCR 12 to sealing set (trade-off: no graceful degradation)
5. Migration: on first boot with EXTA partition available, copy Extension from
   /persist/vault/ to EXTA and switch to partition-based loading
```

This is planned for a future phase after the PERSIST-based split rootfs with erofs + dm-verity is stable.

---

## References

### Code Locations

| Component | Path |
|-----------|------|
| TPM integration | `pkg/pillar/evetpm/tpm.go` |
| PCR measurement | `pkg/measure-config/src/measurefs.go` |
| Attestation | `pkg/pillar/attest/attest.go` |
| Extension Loader (POC) | `pkg/pillar/cmd/extsloader/` |
| Digest verification | `pkg/pillar/cmd/verifier/lib/verifier.go` |
| GRUB squash4 + boot chain | `pkg/grub/rootfs.cfg` |
| GRUB 1st stage config | `pkg/mkimage-raw-efi/make-raw` (inline grub.cfg) |
| Initrd (installer only) | `pkg/mkimage-raw-efi/initramfs-init.patch` |
| Rootfs squashfs build | `pkg/mkrootfs-squash/make-rootfs` |
| Linuxkit rootfs config | `images/rootfs.yml.in` |
| Core rootfs config | `images/rootfs-core.yml.in` |
| Extension rootfs config | `images/rootfs-ext.yml.in` |
| Installer config (split) | `images/installer.yml.in` (rootfs-ext.img bind) |
| Installer script | `pkg/installer/install` (CONFIG HV read, ext copy) |
| HV override (GRUB) | `pkg/grub/rootfs.cfg` (eve-hv-type from CONFIG) |
| HV override (onboot) | `pkg/pillar/cmd/onboot/onboot.sh` |
| Storage init (HV-aware) | `pkg/mkimage-raw-efi/storage-init.sh` |
| Hypervisor runtime dispatch | `pkg/pillar/hypervisor/hypervisor.go` |

### PCR Allocation

```
EVE's sealing PCRs:     {0, 1, 2, 3, 4, 6, 7, 8, 9, 13, 14}
EVE's attestation PCRs: {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

Proposed:
  PCR 12 → Extension Image measurement
```
