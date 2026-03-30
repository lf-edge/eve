# Upstreaming

As noted in [BUILD.md](./BUILD.md), the EVE build process uses many standard off-the-shelf tools, and either modifies or augments them to create an EVE image.

This document explores the ways in which the EVE tools differ from the "standard" tools, and what upstream changes would be necessary to reduce or eliminate EVE's customizations. Obviously, areas wherein EVE is highly unique or special are not candidates for such mainstreaming.

This document is a Work-In-Progress, and should not be considered definitive or final. We are very open to new ideas and sections to add, and are pleased when work is upstreamed, allowing us to remove sections.

The document is divided into two parts:

* tools - tools used to build various images or parts
* components - packages and components that are inserted _into_ built images

## Tools

### makerootfs

[makerootfs.sh](../makerootfs.sh) is a script that runs `linuxkit build` based on the passed config `yml`, outputs a tar stream, and passes the resultant tar stream to [mkrootfs-ext4](../pkg/mkrootfs-ext4) or [mkrootfs-squash](../pkg/mkrootfs-squash), depending on the selected output format. `mkrootfs-<format>` builds the tar stream into an output disk image file with the desired filesystem format (ext4|squashfs).

When we started using linuxkit `linuxkit build -o kernel+squashfs` wasn't available, but it is entirely possible that we can simply transition to `linuxkit build -o raw-efi` or `linuxkit build -o kernel+squashfs` now. **Task:** investigate whether the result of `linuxkit build -o kernel+squashfs` or `linuxkit build -o raw-efi` will provide the desired output.

### makeflash

[makeflash.sh](../makeflash.sh) is a script that creates an empty file of the target disk image size. This target is then passed to [mkimage-raw-efi](../pkg/mkimage-raw-efi), which partitions the provided disk image into the requested partitions, and installs the correct bits in each partition: grub into `efi`, a pre-built rootfs into `imga` and optionally `imgb`, a pre-built config into `config`.

There is no tool that currently does anything close to this. The closest option might be linuxkit, if it were to add support for multiple partitions, with optional inputs into each partition.

### maketestconfig

[tools/makeconfig.sh](../tools/makeconfig.sh) is a script that tars up the contents of [conf/](../conf/), passing the tar stream to [mkconf](../pkg/mkconf), which lays those contents on top of the contents of `/opt/zededa/examples/config` from [pillar](../pkg/pillar/conf) and puts the result in a FAT32 image named `config.img`.

This is a fairly straightforward process - somewhat complicated by the two layers of tarring the local directory up and then overwriting the `pillar` default in a separate container, but not unduly so - and is unlikely to be replaced by any other tool. At best, in its current usage, it can be simplified somewhat as a single container image run.

More relevant and useful is an analysis of the usage of `config` in a production-quality system. It is unlikely that the fixed config in `/opt/zededa/examples/config` or `conf/` will be used in production-scale deployments. We should determine how we want to use `config` in real deployed systems, how it will be installed, where it applies to the device API protocol, and design a full solution.

## Components

### grub

[grub](pkg/grub) applies a series of necessary patches to [upstream GRUB 2.12](https://www.gnu.org/software/grub/). The patches live in [pkg/grub/patches-2.12](../pkg/grub/patches-2.12). The primary way to eliminate the need for a custom GRUB is to upstream these patches. Several patches that existed in previous versions of EVE (based on GRUB 2.06) have already been merged upstream and were dropped during the 2.12 migration.

**Upstream contribution note (as of March 2026):** GRUB moved its canonical repository from GNU Savannah to [GitLab at freedesktop.org](https://gitlab.freedesktop.org/gnu-grub/grub/) on March 13, 2026. Patches are no longer submitted via the old `grub-devel@gnu.org` mailing list; contributions are now made as GitLab Merge Requests. The replacement mailing list is `grub-devel@lists.freedesktop.org`. Any "Task: upstream" items below should target the freedesktop GitLab instance.

EVE's GRUB patches originated from two sources: the [CoreOS fork of GRUB](https://github.com/coreos/grub) (based on GRUB 2.02, last updated 2019) and EVE-specific additions. All patches have been traced back to their original authors and attributed accordingly; the CoreOS-originated commits map to specific upstream hashes in that fork (useful reference for future migrations):

* [`f69a9e0`](https://github.com/coreos/grub/commit/f69a9e0fdcf63ac33906e2753e14152bab2fcd05) — _gpt: start new GPT module_ (Michael Marineau)
* [`508b02fc`](https://github.com/coreos/grub/commit/508b02fc8a1fe58413ec8938ed1a7b149b5855fe) — _gpt: new gptprio.next command for selecting priority based partitions_ (Michael Marineau)
* [`67475f53`](https://github.com/coreos/grub/commit/67475f53e0ac4a844f793296ba2e4af707d5b20e) — _gpt: add search by partition label and uuid commands_ (Michael Marineau)
* [`1545295a`](https://github.com/coreos/grub/commit/1545295ad49d2aff2b75c6c0e7db58214351768e) — _gpt: add search by disk uuid command_ (Alex Crawford)

#### Dropped in 2.12 migration (now upstream)

The following patches from the GRUB 2.06 era were confirmed upstream in GRUB 2.12 and removed:

* `0001-TPM-build-issue-fixing` — struct names corrected upstream
* `0002-video-Allow-pure-text-mode` — superseded by `commands/efi/efitextmode.c`
* `0004-Disabling-linuxefi` — `linuxefi` is proper in 2.12's unified `loader/efi/linux.c`
* `0005-rc-may-be-used-uninitialized` — fixed upstream
* `0009-fat-allow-out-of-range-timestamps` — merged upstream
* `0014-loader-linux-newc-NULL-termination` — merged upstream
* `riscv64/0002-riscv-binutils-2.38` — commit `049efdd72` upstream in 2.12
* `0003-allow-probe-partuuid` — `probe --part-uuid` has been in upstream GRUB since before 2.12, handles both GPT and MBR; no patch needed and `rootfs.cfg` works unchanged with the upstream command

#### Current patches (patches-2.12/)

##### 0001 — Making it possible to export variables from inner contexts of GRUB

Author: Roman Shaposhnik

Exports current GRUB setting vars. Required for `grub.cfg` where we [set global variables from submenus](../pkg/grub/rootfs.cfg). Allows a single boot menu to set options rather than duplicating entries for every combination.

**Task:** Present use case to GRUB upstream and get the patch accepted.

##### 0002 — Adding a capability of a GRUB cat command to deposit to a var, not stdout

Author: Roman Shaposhnik

Extends the `cat` command to write file contents into a GRUB variable instead of printing to stdout. Used in `grub.cfg` to read configuration values from files on the CONFIG partition.

**Task:** Upstream as an extension to the `cat` command.

##### 0003 — set cmddevice

Author: Petr Fedchenkov

Adds a `cmddevice` command that sets the device from which GRUB commands are executed. Required for EVE's two-stage GRUB boot where the second stage must locate its configuration on the correct partition.

##### 0004 — Put removable hard drives detected by UEFI at the end of the drive list

Author: Mikhail Malyshev

Moves UEFI-detected removable drives to the end of GRUB's device enumeration. Prevents removable media (USB drives, etc.) from being incorrectly selected as the boot device ahead of fixed disks.

**Task:** Upstream to GRUB — generally useful behavior for any system with removable media.

##### 0005 — gpt: start new GPT module

Author: Michael Marineau (CoreOS) — [coreos/grub@f69a9e0](https://github.com/coreos/grub/commit/f69a9e0fdcf63ac33906e2753e14152bab2fcd05)

Strict GPT parsing library that exports raw GPT data (headers, partition entries) instead of the generic `grub_partition` structure. Foundation for gptprio and the GPT search commands.

**Task:** This is fully upstream-ready; submit to GRUB upstream.

##### 0006 — gpt: new gptprio.next command for selecting priority based partitions

Author: Michael Marineau (CoreOS) — [coreos/grub@508b02fc](https://github.com/coreos/grub/commit/508b02fc8a1fe58413ec8938ed1a7b149b5855fe)

Adds the `gptprio.next` command that selects the highest-priority active GPT partition. This is the core of EVE's A/B partition boot scheme — GRUB uses it to pick IMGA or IMGB based on the `priority` and `successful` GPT attribute bits.

**Task:** Submit to GRUB upstream — this is the key enabler of A/B boot and would benefit any distro using GPT-based dual-partition updates.

##### 0007 — gpt: add search by partition label and uuid commands

Author: Michael Marineau (CoreOS) — [coreos/grub@67475f53](https://github.com/coreos/grub/commit/67475f53e0ac4a844f793296ba2e4af707d5b20e)

Adds `search.part_label` and `search.part_uuid` commands that search devices by GPT partition label and partition UUID respectively (distinct from filesystem label/UUID). Used in `grub.cfg` to locate EVE partitions by their GPT-assigned identifiers.

**Task:** Submit to GRUB upstream alongside the gpt module.

##### 0008 — gpt: add search by disk uuid command

Author: Michael Marineau (CoreOS), co-developed by Alex Crawford (CoreOS) — [coreos/grub@1545295a](https://github.com/coreos/grub/commit/1545295ad49d2aff2b75c6c0e7db58214351768e)

Adds `search.disk_uuid` command that searches devices by GPT disk UUID. Completes the GPT search trilogy alongside 0007.

**Task:** Submit to GRUB upstream alongside 0007.

##### 0009 — Implement watchdog style menu timeout

Author: Mikhail Malyshev

Resets the boot menu timeout to its initial value on any keypress, rather than stopping the countdown. Prevents a spurious keypress during unattended boot from hanging the device at the GRUB menu indefinitely.

**Task:** Upstream to GRUB — useful default behavior for any headless or appliance system.

##### 0010 — commands: Add measurefs command

Author: Mikhail Malyshev

Adds a `measurefs` command that performs TPM PCR measurements of filesystem contents during boot. Used for static root of trust measurement (SRTM) / measured boot in EVE's TPM-enabled boot flow.

**Task:** Submit to GRUB upstream — TPM measurement of filesystems is broadly useful.

##### 0011 — measurefs: skip measurement when no TPM is present

Author: Petr Fedchenkov

Makes `measurefs` a no-op when no TPM device is found (using `grub_tpm_present()`), rather than failing. Required so the same `grub.cfg` works on both TPM-equipped and non-TPM devices.

##### 0012 — Add dt-fixup EFI protocol

Author: Aleksandrov Dmitriy

Implements support for the `EFI_DT_FIXUP_PROTOCOL`, which allows EFI firmware to apply device-tree fixups before the OS is loaded. Required on arm64 and riscv64 platforms where firmware may need to patch the DTB.

**Task:** Submit to GRUB upstream — relevant for any arm64/riscv64 EFI platform.

##### 0013 — efi: Add getenv command to read EFI variables

Author: Mikhail Malyshev

Adds a `getenv` command that reads an EFI NVRAM variable into a GRUB environment variable. Used in `grub.cfg` to retrieve boot-time configuration stored by the OS or by EVE's update logic in EFI variables.

**Task:** Submit to GRUB upstream — reading EFI variables from GRUB scripts is broadly useful.

##### 0014 — tpm: include EFI status code in "unknown TPM error" message

Author: Mikhail Malyshev

Includes the raw EFI status code in the GRUB error message when a TPM operation returns an unrecognized status. Makes TPM boot failures diagnosable without a debugger.

**Task:** Submit to GRUB upstream — strictly a diagnostic improvement with no functional change.

### devices-trees

[devices-trees](pkg/devices-trees/) adds specific device tree source files and compiles them. This is unlikely to be upstreamed anywhere, but may be extractable. This is likely to be a primary place for extensibility for ARM.

### fw

[fw](../pkg/fw/) adds specific firmware. Most of the added firmware already is in the `alpine:3.8` and above standard distributions, added via `apk add linux-firmware-<platform>`. The package itself uses the standard except in 2 cases, one of which (`ath10k`) is in the process of being upstreamed.

This is unlikely to be replaced anywhere. The closest option is linuxkit, which has no custom firmware solutions at this time. Since it is modular via OCI images, the likely solution is to use a firmware-specific OCI image in the `init` section, which is precisely what we are doing.

### xen

[xen](../pkg/xen/) builds and adds the xen kernel. It downloads the official Xen source, configures and builds it, and extracts the bootable kernel. This, in turn, is used in grub to boot into `dom0`, which then boots into the dom0 kernel, as defined in the linuxkit config `kernel` section.

We do a custom build of the xen kernel for two reasons:

1. Some customization is done for the final `arm64` build. This may be unnecessary, or may be upstream-able to xen.
2. We have not yet validated that all of our required functionality is in the available xen packages. This should be checked.

Further, the boot process is a bit "backwards", at least for the live `rootfs.img`. The actual booted kernel (xen) is installed in `init` while the kernel that xen boots into in `dom0` is in `kernel`, with the customization made available via `grub.cfg`. Ideally, linuxkit would support xen booting directly in the `kernel` section.

### gpt-tools

[gpt-tools](../pkg/gpt-tools) loads a series of gpt partition utilities/tools onto the base filesystem. It adds the following tools:

* `sgdisk` - with specific patches listed in [pkg/gpt-tools/patches](../pkg/gpt-tools/patches)
* `cgpt` - works with ChromeOS-specific GPT partitioning
* [zboot](../pkg/gpt-tools/files/zboot) - a script that is the main entry point for EVE Go code querying and manipulating the state of partitions. It makes it easy to read and set partition information, by wrapping calls to `cgpt`.

The primary purpose of the changes to `sgdisk` and `cgpt` are to support adding additional states on partitions. Normally, GPT partitions have a limited number of attributes. In order to support the a/b partition boot style, we wish to add additional states, notably `active`, `updating` and `unused`. The patches to `cgpt` and `sgdisk` add support for these attributes. Essentially, we are abusing the partition state bits to add our own custom attributes.

We will explore two options:

1. Are there alternate ways to signify the desired partition states using standard tools?
2. If not, can we upstream the additional states, or some form of custom states, to `sgdisk` and `cgpt`?

### dom0-ztools

[dom0-ztools](../pkg/dom0-ztools) inserts a single script, [zen](../pkg/dom0-ztools/zen) onto the base filesystem. `zen` is a utility script that wraps `ctr` to simplify access to containerd containers. This presumably is because the `ctr` commands can be convoluted and hard to remember.

There is a case to be made for upstreaming this into linuxkit itself, at least in the ssh/getty containers.

### mkinitfs

There are two files [initramfs-init](../pkg/mkimage-raw-efi/initramfs-init) and [nlplug-findfs.c](../pkg/mkimage-raw-efi/nlplug-findfs.c) that came directly from Alpine's [initramfs](https://github.com/alpinelinux/mkinitfs) project but they contain a few small tweaks making them applicable to our installation needs.
