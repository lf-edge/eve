# Installer Booting

**Note:** This document describes the EVE installer boot chain. It does not describe the boot chain of the
installed system, or go into firmware, boards, etc. For details, see [BOOTING.md](./BOOTING.md).
The primary purpose of this document is to describe the installer boot chain, to help in debugging issues
or modifying it.

The EVE installer can boot in one of 3 modes:

* raw disk
* ISO
* PXE, i.e. network boot

The installer is built as a minimal image in the format `installer.tar`. It uses a build `.yml` file,
just like the normal EVE runtime rootfs. For more details, see
[../pkg/installer/README.md](../pkg/installer/README.md).

The output of that is `installer.tar`. During normal `make` operations, that is installed in
`dist/<arch>/<version>/installer.tar`. For example, `dist/amd64/0.0.0-master-abcd1234/installer.tar`.

You can create that installer tar by running `make installer.tar` in the root of the repository.
However, all final installer build formats have `installer.tar` as a dependency and will build it for you.

Each of the final formats can be built via:

* `make installer-raw` or just `make installer`
* `make installer-iso`
* `make installer-net`

## Artifacts

The artifacts of each are as follows:

* raw: `dist/<arch>/<version>/installer.raw` - a raw disk image with multiple partitions
* iso: `dist/<arch>/<version>/installer.iso` - an El Torito-compliant ISO image with a hidden `boot.img` compatible with UEFI boot
* net: `dist/<arch>/<version>/installer.net` - a tarball with everything needed to boot off of PXE, specifically an `ipxe.efi.cfg`, the installer ISO, and an `EFI/` boot directory with `grub.cfg` and an architecture-appropriate `BOOT*.EFI` from grub

## Booting

In all cases, the goal is to get to the usual grub booting `grub.cfg` from `installer.tar`, so
that all of the menus and settings are appropriate.

In each format, where the installer gets to that target, the document will mark it with a bold **V**.

### Raw Disk

The raw disk contains an EFI System Partition (ESP), which all UEFI systems can boot from.

The ESP contains:

* several files necessary for booting, including USB and u-boot, not covered here
* `EFI/BOOT/BOOT*.EFI` - the UEFI bootloader, which is a copy of the grub bootloader from the `installer.net`
* `EFI/BOOT/grub.cfg` - the grub configuration file, which is configured to find the next partition with a "boot next" flag, and then boot to it

The "boot next" flag is checked via `gptprio.next`, a grub-specific patch from CoreOS boot. This is the
same mechanism that installed EVE uses to select between IMGA and IMGB. For more details, see comments
on the function `do_efi()` in [../pkg/mkimage-raw-efi/make-raw](../pkg/mkimage-raw-efi/make-raw).

The boot process then is:

1. System starts UEFI firmware
1. UEFI sees the disk
1. UEFI finds the ESP
1. UEFI finds `EFI/BOOT/BOOT*.EFI` appropriate for the architecture
1. `BOOT*.EFI` is grub, which reads `grub.cfg` in the same directory
1. `grub.cfg` finds the next partition with the "boot next" flag, which is the `INSTALLER` partition
1. `grub.cfg` chainloads `EFI/BOOT/BOOTX64.EFI` from the `INSTALLER` partition
1. `BOOTX64.EFI` in the `INSTALLER` partition is the grub bootloader from the `installer.tar`, which loads the usual `grub.cfg` **V**
1. `grub.cfg` sees the file `grub_include.cfg` in the same directory, which sets installer settings
1. `grub.cfg` in the `INSTALLER` partition loads the usual menu

The custom `grub.cfg` is generated inside [make-raw](../pkg/mkimage-raw-efi/make-raw) in the function `do_efi()`.

### ISO

The ISO contains the contents of the `installer.tar`, along with the FAT32 `boot.img` that is used to boot.

The `boot.img` contains just `EFI/BOOT/BOOTX64.EFI`, which is the grub bootloader from the `installer.tar`.

The boot process then is:

1. System starts UEFI firmware
1. UEFI sees the CD
1. UEFI finds the CD is El Torito-compliant, loads the `boot.catalog`
1. UEFI finds the `boot.catalog` points to `boot.img`
1. UEFI loads the `boot.img`
1. UEFI finds `EFI/BOOT/BOOT*.EFI` appropriate for the architecture inside `boot.img`
1. `BOOT*.EFI` is grub, which reads `grub.cfg` from root. However, because this is a CD boot, `root` is set to the CD itself, and *not* the `boot.img`. This means it is the regular `grub.cfg`. **V**
   * It is possible that a UEFI firmware could provide `root` as the FAT32 image, and not the CD. To handle that case, a `grub.cfg` also is placed inside the FAT32 `boot.img`, which finds the CD and chainloads to the `BOOT*.EFI` inside the CD.
1. `grub.cfg` sees the file `grub_include.cfg` in the same directory, which sets installer settings
1. `grub.cfg` in the `INSTALLER` partition loads the usual menu
1. `grub.cfg` recognizes that it is a CD boot, sets:
   * `kernel /boot/kernel`
   * `initrd /boot/initrd.img`
1. `initrd.img` mounts the CD and calls `switch_root`.

The custom `grub.cfg` inside the `boot.img` is generated inside [make-efi](../pkg/mkimage-iso/make-efi).

### PXE

The `installer.net` is a tar file containing the following:

* `installer.iso`
* `ipxe.efi.cfg` - a configuration file for iPXE
* `EFI/BOOT/BOOT*.EFI` - the UEFI bootloader, which is a copy of the grub bootloader from the `installer.tar`
* `EFI/BOOT/grub.cfg` - a basic grub configuration file, generated as part of making the `tar`

The boot process then is:

1. System starts UEFI firmware
1. UEFI runs through its boot process until it starts PXE
1. PXE goes through the usual process, dhcp and then tftp, not covered in detail here
1. PXE downloads [ipxe.efi.cfg](../pkg/eve/installer/ipxe.efi.cfg) from the tftp server
1. `ipxe.efi.cfg` sets console variables and then chainloads grub from the tftp server as `${url}/EFI/BOOT/BOOT*.EFI`
1. `BOOT*.EFI` is grub, which reads `grub.cfg` from the same directory on the tftp server
1. `grub.cfg` is the custom grub configuration file described as part of the net installer creation process
1. `grub.cfg` determines the source directory and mounts `${url}/installer.iso` via loopback as device `loop`
1. `grub.cfg` sets `netboot=true`, so that later stages can know it was booted from the network
1. `grub.cfg` hands control to `(loop)/EFI/BOOT/grub.cfg` from the loop mounted ISO **V**
1. `grub.cfg` recognizes that it is a network boot, sets:
   * `kernel /boot/kernel`
   * `initrd /boot/initrd.img newc:/rootfs_installer.img:($root)/rootfs_installer.img` - this loads the installer rootfs
     in the initramfs as a file, read out of the loop mounted ISO. If the ISO carries a top-level `config.img`
     override, it is loaded the same way and passed as `rootaddmount=/config.img:/config.img`
1. `initrd.img` mounts `/rootfs_installer.img` and calls `switch_root`.

Note that the payload is read from the ISO that grub already has open as `loop`, rather than by naming
`($install_part)/installer.iso` as the initrd source. The latter is a second URL, so it makes the whole ISO
cross the network twice - once for grub to read the kernel and initrd out of, and once as the initramfs payload.

For the same reason, prefer serving the netboot directory over HTTP rather than TFTP. Grub's HTTP transport
implements `seek` with a `Range` request, so grub only transfers the ISO extents it actually reads; its TFTP
transport has no `seek`, so every backward seek restarts the transfer from byte 0 and discards forward, which
for a ~500MB ISO means several full transfers before the kernel even starts.

#### Fetching the ISO over HTTP

Grub inherits its device from whatever chainloaded it, so when iPXE loads `BOOT*.EFI` over TFTP,
`$cmddevice` is `tftp,<server>` and the ISO is read over TFTP as well. To read it over HTTP instead,
override `$cmddevice` in the `EFI/BOOT/grub.cfg` of the served directory, before the `loopback` line:

```grub
set cmddevice=http,192.168.1.1
loopback loop0 ($cmddevice)/installer.iso
set root=loop0
set isnetboot=true
export isnetboot
configfile ($root)/EFI/BOOT/grub.cfg
```

A non-default port is given as `http,192.168.1.1:8080`.

Note that `($cmddevice)/installer.iso` resolves from the root of that device, i.e.
`http://192.168.1.1/installer.iso`, and *not* relative to the directory grub itself was loaded from.
If the netboot tarball is served from a subdirectory, spell the path out instead, e.g.
`loopback loop0 (http,192.168.1.1)/eve/installer.iso`.
