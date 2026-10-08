# Linux Firmware in EVE

Many drivers load firmware from `/lib/firmware` when they probe a device:
Wi-Fi and Bluetooth adapters, GPUs, some network and storage controllers, and
accelerators. EVE ships this firmware in [pkg/fw](../pkg/fw), which goes into the
`init` section of the rootfs and installer images. The same package also builds
the early CPU microcode image, `/boot/ucode.img`.

This document describes where the firmware comes from, how EVE selects what to
ship, how firmware relates to the kernel version, and what to do when either
side changes. The kernel itself is described in [KERNEL.md](KERNEL.md).

## Sources

The `build` stage of [pkg/fw/Dockerfile](../pkg/fw/Dockerfile) installs every
source below into `/lib/firmware`. Each source is pinned by a version variable
in the Dockerfile and registered with `register-sbom-pkg.sh`, so that it appears
in the SBOM. A new source needs both.

| Source | Version variable | Notes |
|---|---|---|
| [linux-firmware](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git) | `LINUX_FIRMWARE_VERSION` | Most of the firmware, installed by its own `make install`, which also creates the links its `WHENCE` file declares |
| [wireless-regdb](https://wireless.wiki.kernel.org/en/developers/regulatory/wireless-regdb) | `WIRELESS_REGDB_VERSION` | `regulatory.db` for cfg80211 |
| Hailo-8 firmware | `HAILO_FW_VERSION` | Must match the version of the out-of-tree `hailo_pci` driver the kernel builds (`HAILO_V4_VERSION` in eve-kernel's `Dockerfile.gcc`) |
| NVIDIA L4T firmware | `JETPACK*_DEB` | Jetson platforms, chosen by `PLATFORM` |
| Raspberry Pi firmware-nonfree and bluez-firmware | `RPI_FIRMWARE_VERSION`, `RPI_BT_FIRMWARE_VERSION` | arm64 only |
| [rtw88 firmware](https://github.com/lwfinger/rtw88) | `RTL8822_FW_VERSION` | Used by the per-device selection for arm64 and riscv64 |
| Intel and AMD CPU microcode | `INTEL_UCODE_VERSION`, `AMD_UCODE_VERSION` | Built into `/boot/ucode.img`, not `/lib/firmware`; the firmware selection below does not apply to it |

## What the image ships

The `build` stage holds about 2 GiB of firmware, far more than the rootfs has room
for: the amd64 rootfs must stay under `ROOTFS_MAXSIZE_MB` (290 MiB), which
`make rootfs` enforces. The image therefore ships a selection, and how it is
made depends on the architecture:

- **amd64** ships exactly the files listed in
  [pkg/fw/firmware-amd64.txt](../pkg/fw/firmware-amd64.txt). The list is
  generated from the kernel, as described below.
- **arm64 and riscv64** ship a per-device selection written by hand in the
  `compactor-common` stage of the Dockerfile. Most of their firmware is chosen
  by board name (device tree compatible strings, NVRAM per board), which needs
  rules of its own.

### The generated list

[tools/update-fw-lists.py](../tools/update-fw-lists.py) writes
`pkg/fw/firmware-<arch>.txt` from the rules in
[pkg/fw/firmware-select.txt](../pkg/fw/firmware-select.txt). For each
architecture with rules, it:

1. Reads the kernel images that `make kernel-tag` pins for the platforms the
   rules name (for amd64: `generic` and `rt`).
1. Collects every firmware name the kernels declare with `MODULE_FIRMWARE`:
   the `firmware=` entries in each module's modinfo, and in
   `modules.builtin.modinfo` for built-in drivers.
1. Builds the `build` stage of pkg/fw and resolves each name against its
   `/lib/firmware` the way the driver loads it:
   - a symlink is shipped together with its target;
   - a pattern that a module declares, such as brcmfmac's per-board NVRAM
     `brcm/brcmfmac*-pcie.*.txt`, is expanded to the files it matches;
   - iwlwifi declares one name per MAC and RF type, at the newest firmware API
     it supports. At load time it fills in the silicon steps and the CDB flag
     from the hardware, and walks the API down to its minimum. Every firmware
     prefix the driver can build therefore gets its newest version the driver
     accepts, plus its `.pnvm` file.
1. Applies the rules in `firmware-select.txt`, then writes the list.

The rules are:

| Rule | Meaning |
|---|---|
| `<arch> platforms <p>...` | Read the kernels `make kernel-tag` pins for these platforms |
| `<arch> module <m> [<re>]` | Ship the firmware module `<m>` declares, only names matching `<re>` if given; `*` is every module and built-in driver |
| `<arch> exclude <re>` | Leave out declared names, or files a declared pattern matches, that match `<re>` |
| `<arch> extra <glob>` | Ship files that no module declares because the driver builds their names at runtime. The tool fails if a glob matches nothing |

Every `exclude` and `extra` carries a comment saying why, usually the device it
is for.

The header of the generated list records the kernel images it was generated
from, and every name a module declares that the firmware tree lacks:

```text
# missing: ath10k_pci ath10k/QCA6174/hw3.0/firmware-5.bin
# missing: rsi_usb rs9113_wlan_qspi.rps
```

A missing name is usually harmless. The driver also accepts another version,
which is in the list when the tree has one (ath10k tries firmware API 6 down to
2, iwlwifi walks its API down). Or the declaration is stale: `rsi` declares
`rs9113_wlan_qspi.rps` but loads `rsi/rs9113_wlan_qspi.rps`. Or the file was
never published to linux-firmware: Apple's Broadcom parts, Realtek SDIO
Bluetooth, and chips newer than the kernel. A name that newly appears after a
kernel or firmware update, however, may be a driver that lost its firmware, and
it shows up in the diff of the list.

`make check-fw-lists` regenerates the lists without writing them, and fails with
a diff if a committed list is out of date. CI runs it on every change to the
kernel pins (`kernel-version.mk`, `kernel-commits.mk`), so a kernel update that
does not regenerate the lists fails its pull request instead of leaving a driver
without firmware.

## Kernel and firmware versions

A linux-firmware release is a dated snapshot (`20260916`). Its version says
nothing about the kernels it supports. What ties a kernel to the firmware is
file names: a driver asks for specific files, and a release either has them or
does not.

The kernel's
[firmware guidelines](https://docs.kernel.org/driver-api/firmware/firmware-usage-guidelines.html)
set the rules both sides follow: users switching to a newer kernel must not have
to install newer firmware, and updated firmware must not break older kernels.
Firmware that changes its interface gets a new file name, such as a new major
version or API number, and the old file stays. Vendors remove old files only
when no maintained LTS kernel loads them anymore. Intel's iwlwifi cleanups, for
example, are named after the LTS kernels they no longer serve.

EVE ships only LTS kernels. That gives two practical rules:

- **The newest linux-firmware release works.** It keeps every file a
  maintained LTS kernel needs, so when updating, take the newest release.
- **A kernel needs a release about as new as itself.** The firmware for the
  newest hardware a kernel supports reaches linux-firmware around the kernel's
  merge window. Kernel 6.18, released on 2025-11-30, finds every file it
  declares in linux-firmware 20251111 and later.

Two cases fall outside these rules:

- **Out-of-tree drivers.** The guidelines do not cover them. Hailo-8 firmware,
  for example, must match the `hailo_pci` version exactly.
- **Hardware newer than the kernel.** If a vendor publishes firmware only in
  versions the driver does not accept, no linux-firmware release helps; the
  hardware needs a newer kernel. iwlwifi in 6.18 accepts firmware up to core 99,
  while the first firmware for Intel's Wi-Fi 7 `sc` parts with the FM radio is
  core 101.

## Procedures

### After updating the kernel

1. Update the kernel pins as described in [KERNEL.md](KERNEL.md).
1. Regenerate the lists:

   ```bash
   tools/update-fw-lists.py
   ```

1. Review the diff of `pkg/fw/firmware-*.txt`:
   - the `# kernel:` lines name the new kernel images;
   - added files come from drivers the kernel now builds, or from firmware
     versions the drivers now accept;
   - removed files come from drivers the kernel no longer builds, or from
     firmware versions the drivers no longer accept. Check that this is
     intended, for example after a kernel configuration change;
   - for each new `# missing:` line, find out whether the driver falls back to
     another file. If it does not, and EVE supports the hardware, update
     linux-firmware (see below) or add an `extra` rule.
1. If the version of an out-of-tree driver changed, such as `hailo_pci`, update
   its firmware in `pkg/fw/Dockerfile` to match.
1. Build and check the size limit:

   ```bash
   make pkg/fw rootfs
   ```

1. Commit the regenerated lists together with the kernel update.

To check a kernel that is not pinned yet, such as a local build, set
`KERNEL_TAG`; the tool then reads that image for every platform in the rules.
Do not commit a list generated this way.

```bash
KERNEL_TAG=$(make -C /path/to/eve-kernel -s -f Makefile.eve docker-tag-gcc) tools/update-fw-lists.py amd64
```

### After updating linux-firmware or another source

1. Change the version variable in `pkg/fw/Dockerfile`. `AMD_UCODE_VERSION`,
   the AMD microcode, is taken from linux-firmware as well and usually moves
   with `LINUX_FIRMWARE_VERSION`.
1. Build `make pkg/fw`. linux-firmware creates the links its `WHENCE` file
   declares. If a new release starts declaring a link that pkg/fw also creates,
   the build fails with "File exists"; remove the duplicate `ln` from the
   Dockerfile.
1. Regenerate the lists with `tools/update-fw-lists.py` and review the diff as
   above. Typical changes are files moving to a newer version of the same
   firmware, and `# missing:` lines going away. A list that is not regenerated
   fails the build if it names a file the new release no longer has, or a link
   whose target the list lacks.
1. Build `make pkg/fw rootfs` and check the size limit.
1. Test the hardware the update is for, see
   [Checking firmware on a device](#checking-firmware-on-a-device).

### Adding firmware for a device

1. Find the driver and the firmware it loads. If the driver declares its
   firmware, and the kernel builds the driver, the firmware is in the list
   already. If the kernel does not build the driver, enable it in the kernel
   configuration first ([KERNEL.md](KERNEL.md)) and regenerate the lists.
1. If the driver builds the firmware name at runtime (look for
   `request_firmware` in its source), add an `extra` rule to
   `pkg/fw/firmware-select.txt` with a comment naming the device, and
   regenerate the lists.
1. If the firmware is not in linux-firmware, download it in the `build` stage of
   `pkg/fw/Dockerfile`, pin its version, register it for the SBOM, and then add
   an `extra` rule (amd64) or a `COPY` in `compactor-common` (arm64, riscv64).
1. Firmware takes rootfs space for every EVE user. Ship only what the device
   loads, not whole directories.

### Checking firmware on a device

The kernel log names every file a driver asked for and could not load:

```text
Direct firmware load for iwlwifi-so-a0-gf4-a0-89.ucode failed with error -2
```

Some drivers try several names in turn, so failures followed by a successful
load are normal: iwlwifi walks its firmware API down, and ath10k tries
`board-2.bin` before `board.bin`. A driver that ends without loading anything
is missing its firmware. Compare the name with `pkg/fw/firmware-<arch>.txt` and
with linux-firmware.

## See Also

- [KERNEL.md](KERNEL.md) - How EVE's kernel is built and updated
- [WIRELESS.md](WIRELESS.md) - Wireless support in EVE
- [HARDWARE-BRINGUP.md](HARDWARE-BRINGUP.md) - Bringing EVE up on new hardware
- [SBOM-AND-SOURCES.md](SBOM-AND-SOURCES.md) - SBOM generation
