# Intel iGPU Passthrough in EVE OS

This document explains how Intel integrated GPU (iGPU) passthrough works in EVE OS,
what was wrong with the original approach, how it is implemented today, what works and
what does not, and what needs to be updated when Intel releases new GPU generations.

---

## Background: what the iGPU needs from firmware

Before the OS driver (i915 on Linux, or the Intel display driver on Windows) can
initialize the Intel iGPU in a VM, two things must be set up in the guest PCI config
space by firmware — either BIOS or UEFI — during the VM boot phase.

### OpRegion — ASLS register (PCI config offset 0xFC)

The OpRegion is an Intel-defined in-memory structure populated by the host platform
firmware. It contains the **Video BIOS Table (VBT)** which describes the physical display
topology: which ports exist (HDMI, DisplayPort, eDP), EDID overrides, hotplug
configuration, panel sequencing, and more.

Without it, the i915 driver has no idea which physical connectors are wired up. DP/HDMI
detection and hotplug will not work.

QEMU copies the host's OpRegion into the VM via the fw_cfg entry `etc/igd-opregion` when
`x-igd-opregion=on` is set on the vfio-pci device. Guest firmware must:

1. Read this fw_cfg file
2. Allocate a reserved memory region below 4 GB (ACPI NVS, 4 KB aligned)
3. Copy the content into it
4. Write the 32-bit physical address into ASLS (PCI config offset 0xFC) of the iGPU

### Stolen memory — BDSM register (PCI config offset 0x5C or 0xC0)

The Intel iGPU reserves a region of RAM during POST for the Graphics Translation Table
(GTT). The base address of this stolen region is held in the BDSM register. The i915
driver reads BDSM to locate it.

If BDSM is zero or contains the host physical address (not a valid guest address), i915
fails to initialize the GPU.

QEMU writes the stolen memory size to fw_cfg as `etc/igd-bdsm-size` (8-byte little-endian
integer). Guest firmware must:

1. Read this fw_cfg file to get the size
2. Allocate a 1 MB-aligned reserved memory region below 4 GB
3. Write the physical address into BDSM

The register width changed with Intel Gen11:

- **Gen6–Gen10** (Sandy Bridge through Comet Lake): BDSM is a **32-bit** register at
  offset **0x5C**
- **Gen11+** (Ice Lake, Tiger Lake, Alder Lake, Raptor Lake, and later): BDSM is a
  **64-bit** register at offset **0xC0**

This distinction is critical and was the main bug in the original EVE implementation.

---

## Why SeaBIOS / i440fx works

SeaBIOS is a legacy BIOS. When it encounters a PCI option ROM (the VBIOS — the 64 KB
Video BIOS built into the IGD device), it executes it in 16-bit real mode. The VBIOS:

1. Checks the device is at guest BDF `00:02.0` (hardcoded)
2. Reads the LPC/ISA bridge at `00:1f.0` to verify device IDs match real Intel hardware
3. Reads the GMCH register at `00:00.0` to find stolen memory size
4. Allocates stolen memory, writes address to BDSM
5. Initializes the framebuffer

For this to work in a VM under i440fx:

- The device must be at guest BDF `00:02.0`
- A fake LPC bridge must exist at `1f.0` with host device IDs copied in via `x-igd-lpc`
- The i440fx machine type has no permanent occupant at `1f.0`, so QEMU creates a
  `vfio-pci-igd-lpc-bridge` device there

**i440fx works because slot `1f.0` is free** and can host the fake LPC bridge.

---

## Why q35/UEFI fails without special handling

UEFI/OVMF in EVE has no CSM (Compatibility Support Module). The VBIOS never executes.
Nobody sets BDSM. Nobody allocates OpRegion memory. The OS driver fails to initialize.

The q35 machine type permanently occupies `1f.0` with the ICH9 LPC controller. QEMU
explicitly refuses to enable the legacy VBIOS path when it finds a real device there
(`hw/vfio/igd.c`: "cannot support legacy mode due to existing devices at 1f.0", also
called "Sorry Q35" in comments). `x-igd-lpc` — the QEMU option that copies LPC bridge
device IDs for the VBIOS path — does nothing useful on q35/UEFI.

The additional problem was in QEMU's `vfio_probe_igd_bar4_quirk()`: the code that writes
`etc/igd-bdsm-size` to fw_cfg and emulates BDSM/GMCH was placed *after* the BDF and LPC
bridge checks. On q35, the "Sorry Q35" path exits early before reaching that code, so the
fw_cfg entry is never written and BDSM is never emulated.

---

## The correct approach: EFI Option ROM with IgdAssignmentDxe

### VfioIgdPkg

Upstream OVMF maintainers declined to accept IGD-specific code (TianoCore Bug #935).
The solution is a standalone EFI Option ROM delivered as `romfile=` on the vfio-pci
device. The project that implements this is
[VfioIgdPkg](https://github.com/tomitamoeko/VfioIgdPkg).

VfioIgdPkg builds `igd.rom`, an EFI Option ROM containing:

- **IgdAssignmentDxe** — sets up OpRegion and BDSM; this is the required component
- **PlatformGopPolicy** — implements the protocol needed by the proprietary Intel GOP
  driver for pre-OS framebuffer; only needed if a proprietary GOP ROM is also loaded

### How it works end to end

1. EVE builds `igd.rom` from VfioIgdPkg as part of `pkg/uefi` and ships it in the image.
2. When an Intel iGPU is configured for passthrough, EVE's KVM hypervisor adds
   `romfile=<path to igd.rom>` to the vfio-pci device arguments and enables
   `x-igd-opregion=on`.
3. The iGPU is placed at guest BDF `00:02.0` (required by VfioIgdPkg's BDSM allocation
   path).
4. OVMF's PCI bus driver discovers the EFI ROM on the device (identified by EFI ROM
   header, not the legacy `0x55 0xAA` signature) and loads `IgdAssignmentDxe.efi` as a
   DXE driver.
5. `IgdAssignmentDxe` runs during the DXE phase:
   - Reads `etc/igd-opregion` from fw_cfg, allocates ACPI NVS memory below 4 GB, copies
     the OpRegion content, and writes the guest physical address to ASLS (0xFC).
   - Registers a PciIo notification callback; when the iGPU PciIo protocol appears, it
     reads the GMS field from the (emulated) GMCH register, allocates 1 MB-aligned
     reserved memory for stolen memory, and writes the guest physical address to BDSM
     (0x5C for Gen6–Gen10, 0xC0 for Gen11+).
6. The OS driver (i915 / Intel display driver) initializes successfully.

### Changes to QEMU's vfio-igd quirk

The QEMU patches in `pkg/xen-tools` (patches 08–11) rework `hw/vfio/igd.c`:

**Patch 08 — igd_gen() backport**: upstream's `igd_gen()` returns correct generation
numbers for Gen7 through Gen12 (Haswell through Raptor Lake).  The old function returned
8 for all unrecognised device IDs, making generation-specific checks (BDSM register
offset, GMS encoding) ineffective on Gen9+ hardware.

**Patch 09 — main rework of `vfio_probe_igd_bar4_quirk()`**:

- **GMCH emulation, `etc/igd-bdsm-size` fw_cfg write, and BDSM emulation are moved
  before the BDF/LPC bridge checks.** On q35 the "Sorry Q35" path exits early; without
  this move, those registers are never set and `IgdAssignmentDxe` cannot do its job.
- **BDSM is emulated at the correct PCI config offset**: 0x5C (32-bit) for Gen6–Gen10,
  0xC0 (64-bit) for Gen11+.  Initialized to zero so `IgdAssignmentDxe`'s idempotency
  guard (skip if BDSM ≠ 0) is not falsely triggered by the host physical address.
- **GMS is preserved** in the emulated GMCH register.  The guest driver reads GMS to
  determine stolen memory size; zeroing it caused the Windows driver to crash (no
  stolen memory available).  Upstream QEMU does not zero GMS.
- **Stale GTT entries are cleared** before the BDF check.  After host POST the GTT
  contains entries pointing to host physical addresses, causing IOMMU faults.
- **GMS encoding for Gen9+ Atom SKUs** (codes 0xf0–0xff, 4 MB granularity) is fixed to
  match the Linux kernel's `i915_gem_stolen.c`.
- The generation check is fixed to accept any recognized generation (`gen >= 0`) instead
  of the old hard-coded `gen == 6 || gen == 8` which silently blocked Gen9–Gen12 devices.

**Patch 10 — BAR0 BDSM MMIO mirror** (backported from upstream): the GPU reads BDSM
through BAR0 MMIO at offset `0x1080C0` as well as PCI config space.  Without this
quirk, the MMIO read returns the host physical address while PCI config returns the
emulated guest PA.  The driver sees conflicting values and crashes.  This was the
critical missing piece for Tiger Lake and other Gen11+ devices.

Based on upstream QEMU commits:
- [`11b5ce95`](https://github.com/qemu/qemu/commit/11b5ce95beecfd51d1b17858d23fe9cbb0b5783f)
  "vfio/igd: add new bar0 quirk to emulate BDSM mirror" by Corvin Köhne
- [`f926baa0`](https://github.com/qemu/qemu/commit/f926baa03b7babb8291ea4c1cbeadaf224977dae)
  "vfio/igd: emulate BDSM in mmio bar0 for gen 6-10 devices" by Tomita Moeko

---

## What works and what does not

| Feature | Status | Notes |
| ------- | ------ | ----- |
| i915 / Intel display driver initialization | ✓ Works | OpRegion + BDSM set correctly |
| DP / HDMI output in the guest OS | ✓ Works | VBT from OpRegion describes connectors |
| Hotplug detection (DP, HDMI) | ✓ Works | HPD interrupts forwarded via OpRegion |
| Display connector topology | ✓ Works | |
| Multiple monitors | ✓ Works | Driver-managed |
| Windows Intel display driver (no Code 43) | ✓ Works | |
| UEFI framebuffer during firmware phase | ✗ Not available | Requires proprietary Intel GOP driver |
| Pre-OS graphical output | ✗ Not available | Same reason |
| Gen12+ (Meteor Lake, Arrow Lake, Lunar Lake) OpRegion | ✓ Works | BDSM quirk not needed (LMEMBAR) |

Pre-OS display requires `IntelGopDriver.efi`, the proprietary Intel GOP driver from the
host platform firmware. EVE's design does not depend on pre-OS display. If pre-OS display
is needed in a future use case, a proprietary GOP ROM can be placed alongside `igd.rom`
and loaded as a second option ROM on the device.

---

## Supported Intel GPU generations

VfioIgdPkg supports the following generations:

| igd_gen() | BDSM register | Microarchitectures | PCI Device ID prefix |
| --------- | ------------- | ------------------ | -------------------- |
| 6 | 32-bit 0x5C | Sandy Bridge, Ivy Bridge | `0x01xx` |
| 7 | 32-bit 0x5C | Haswell, Valleyview/Bay Trail | `0x04xx`, `0x0axx`, `0x0cxx`, `0x0dxx`, `0x0fxx` |
| 8 | 32-bit 0x5C | Broadwell, Cherryview | `0x16xx`, `0x22xx` |
| 9 | 32-bit 0x5C | Skylake, Kaby Lake, Coffee Lake, Comet Lake, Gemini Lake, Broxton | `0x19xx`, `0x59xx`, `0x3exx`, `0x9Bxx`, `0x31xx`, `0x_a84` |
| 11 | 64-bit 0xC0 | Ice Lake, Elkhart Lake, Jasper Lake | `0x8Axx`, `0x45xx`, `0x4Exx` |
| 12 | 64-bit 0xC0 | Tiger Lake, Rocket Lake, Alder Lake, Raptor Lake | `0x9Axx`, `0x4Cxx`, `0x46xx`, `0xA7xx` |
| -1 (unknown) | No BDSM (LMEMBAR) | Meteor Lake (`0x7Dxx`), Arrow Lake, Lunar Lake (`0x64xx`), Panther Lake | not yet in `igd_gen()` |

### Meteor Lake and later (no BDSM)

Starting from Meteor Lake, Intel moved stolen memory access to LMEMBAR (MMIO BAR2)
and **removed the BDSM register** from PCI config space. For these devices:

- `IgdAssignmentDxe` recognises these devices (they are in VfioIgdPkg's device table
  with `GetStolenSize = NULL` and `&NullPrivate`), so it **skips stolen memory setup
  entirely** and only sets up OpRegion (ASLS). It never reads `etc/igd-bdsm-size` —
  VfioIgdPkg calculates stolen size from GMS internally, so a missing fw_cfg entry is
  irrelevant.
- OpRegion passthrough works via `x-igd-opregion=on`, which is independent of
  `igd_gen()` and the vfio-igd BAR4 quirk. EVE's `kvm.go` always enables this for
  Intel iGPUs.
- The QEMU `igd_gen()` function does not yet recognise Meteor Lake+ device IDs
  (returns -1), so GMCH/BDSM emulation and the BAR0 mirror are skipped. This is
  correct — there is no BDSM to emulate.
- **Meteor Lake+ may already work** with no QEMU changes needed: OpRegion is handled,
  stolen memory is accessed through LMEMBAR (BAR2) which VFIO passes through as a
  normal BAR, and VfioIgdPkg skips BDSM setup. The only thing to verify is that the
  guest driver's LMEMBAR access works correctly through VFIO BAR passthrough.

---

## Updating EVE for a new Intel iGPU generation

When Intel releases a new GPU generation, check the following in order:

### 1. VfioIgdPkg device table

The primary check: does the new device ID appear in VfioIgdPkg's device table?

- Repository: <https://github.com/tomitamoeko/VfioIgdPkg>
- File: `IgdAssignmentDxe/IgdPrivate.c` — look for the `IgdIds` array
- If the new Device ID is missing, open an issue or PR against VfioIgdPkg
- After a new VfioIgdPkg commit is available, update `VFIOIGD_COMMIT` in
  `pkg/uefi/Dockerfile` and rebuild

### 2. BDSM register location

Check if the new generation uses a new BDSM register offset or width:

- Intel publishes graphics PRM (Programmer's Reference Manual) at
  <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/>
- Look for "Base Data of Stolen Memory" in the PCI config space register map
- If the offset or width changed, `IgdAssignmentDxe/IgdAssignment.c` in VfioIgdPkg needs
  a new generation handler, and the QEMU patch in `pkg/xen-tools` may also need updating

### 3. QEMU vfio-igd quirk

Check `hw/vfio/igd.c` in the upstream QEMU repository:

- The `igd_gen()` function maps PCI Device IDs to generations — new IDs must be added
- The `GetStolenSize()` variant for the new generation must handle any GMS encoding
  changes (check Linux kernel `drivers/gpu/drm/i915/gem/i915_gem_stolen.c` for reference)
- If upstream QEMU already has support, the patch in `pkg/xen-tools` should be rebased
  onto the newer xen-qemu base

### 4. EDK2 / OVMF compatibility

- VfioIgdPkg tracks EDK2 stable releases; check VfioIgdPkg's `VfioIgdPkg.dsc` for any
  new EDK2 library dependencies
- Update `EDK_VERSION` and `EDK_COMMIT` in `pkg/uefi/Dockerfile` if needed
- Regenerate edk2 patches in `pkg/uefi/edk2-patches/edk2-stable<version>/` against the
  new EDK2 base (use `git apply --ignore-whitespace` for CRLF-tolerant patch application,
  and `git format-patch` from within an actual edk2 checkout to preserve CRLF in context
  lines)

### 5. Stolen memory size encoding

If a new generation introduces new GMS encoding codes in the GMCH register, update both:

- VfioIgdPkg's `IgdAssignmentDxe/IgdPrivate.c` (`GetStolenSize()`)
- The QEMU patch (`pkg/xen-tools/patches-4.19.0/x86_64/09-vfio-igd-q35-uefi-bdsm-opregion.patch`)
  — specifically the GMS decoding block before the fw_cfg write

---

## Component map

| Component | File | Role |
| --------- | ---- | ---- |
| UEFI Option ROM build | `pkg/uefi/Dockerfile`, `pkg/uefi/build.sh` | Builds `igd.rom` from VfioIgdPkg |
| EFI Option ROM (runtime) | `pkg/xen-tools/` ships `igd.rom` to host rootfs | Loaded by OVMF; runs `IgdAssignmentDxe` |
| KVM hypervisor integration | `pkg/pillar/hypervisor/kvm.go` | Detects iGPU, sets `romfile=`, BDF, opregion |
| QEMU igd_gen() backport | `pkg/xen-tools/.../08-vfio-igd-backport-igd-gen.patch` | Gen7–Gen12 device ID detection |
| QEMU vfio-igd rework | `pkg/xen-tools/.../09-vfio-igd-q35-uefi-bdsm-opregion.patch` | GMCH/BDSM/fw_cfg/GTT for q35/UEFI |
| QEMU BAR0 BDSM mirror | `pkg/xen-tools/.../10-vfio-igd-bar0-bdsm-mirror.patch` | Intercepts BAR0 MMIO BDSM reads |
| EDK2 base | `pkg/uefi/edk2-patches/edk2-stable*/` | EVE-specific patches on top of EDK2 |
