# Booting EVE

Every time an Edge Node running EVE is powered on or rebooted, the first piece of software
that gets executed is firmware code. The job of the firmware code is to initialize the
hardware just enough to pass control to a custom, operating system specific bootloader
(note that given how peculiar the job of the firmware is, sometimes it doesn't even get
executed by a main CPU, but rather runs on something like a GPU). EVE is currently supporting
the following firmware implementations:

* generic [UEFI firmware](https://en.wikipedia.org/wiki/Unified_Extensible_Firmware_Interface) on both x86 and ARM
* legacy [PC BIOS](https://en.wikipedia.org/wiki/BIOS) on x86 and in the virtualized environments with support for nested virtualization (such as on Google Compute Platform)
* open source [Coreboot](https://en.wikipedia.org/wiki/Coreboot) via the legacy PC BIOS payload
* board specific [u-boot](https://en.wikipedia.org/wiki/Das_U-Boot) firmware (such as on Raspbery Pi ARM platform)

EVE has standardized on GRUB as a bootloader that has to run in all of the initial environments,
although in the future we may provide direct, custom implementations that would be natively integrated
into each of the firmware implementations we support (e.g. EVE UEFI payload, syslinux, coreboot payload
and custom u-boot eve commands).

An important design goal for EVE was to avoid custom, per-board images and make sure that a single
image formatted with a [GPT partition table](https://en.wikipedia.org/wiki/GUID_Partition_Table)
can successfully boot under all of the firmware implementations EVE needs to support (even the
ones that don't natively understand GPT partitioned disks - such as legacy PC BIOS). The following
sections walk you through various boot sequences all using a single EVE disk image.

Make sure to familiarize yourself with the implementation details of [make-raw](../pkg/mkimage-raw-efi/make-raw)
since it is the main entry point into how EVE formats the disks it expects to be booted from.

## Boot time artifacts

Before we proceed describing each type of boot flow in details, let us first establish what kind of boot artifacts are required for EVE to boot. These are:

1. rootfs image (either a [squashfs](https://www.kernel.org/doc/html/latest/filesystems/squashfs.html) or [ext4](https://www.kernel.org/doc/html/latest/filesystems/ext4/index.html))
2. 2nd stage GRUB (in UEFI format)
3. type-1 hypervisor ([Xen](https://xenproject.org/) or [ACRN](https://projectacrn.org/))
4. Dom0 linux kernel (this doubles as type-2 hypervisor for KVM)
5. Optional Alpine-derived initramfs [init entrypoint](https://gitlab.alpinelinux.org/alpine/mkinitfs) as a compressed cpio
6. Optional container that performs [EVE installation](../pkg/mkimage-raw-efi/install) as a compressed cpio
7. Optional extra files (e.g. content of config partition) as a compressed cpio

While EVE bootable images come in at least two different flavors [installer](https://github.com/lf-edge/eve/blob/master/docs/BUILD.md#using-an-installer-image) and [live](https://github.com/lf-edge/eve/blob/master/docs/BUILD.md#installing-a-live-image) the boot flow and boot artifacts are all the same. Therefore, the only difference between an installer and a live image are all the optional boot artifacts #5-#7. In fact, the distinction is so blurry that an installer image that booted on the box and put all the required bits on disk can continue running effectively becoming a live image without the need for a reboot.

Since artifacts #2-#5 are physically embedded inside of the rootfs image (artifact #1) a capable firmware (such as latest versions of u-boot) should be able to boot EVE with only having access to that single binary. However, since we have to deal with less capable firmware implementations (such as UEFI and legacy BIOS - see below) we have to leverage 1st stage GRUB or iPXE to parse rootfs image it in order to get access to artifacts #2-#5. This parsing can happen either via reading required portions of rootfs image from disk on demand (via GRUB's [loopback booting](https://www.gnu.org/software/grub/manual/grub/html_node/Loopback-booting.html)) or by first loading rootfs image to memory (via iPXE extensions). The fact that the size of rootfs image is deliberately kept very small, makes both of these methods roughly similar when it comes to performance and overhead. Still, it is an overhead and whenever possible EVE tries to rely on rootfs image sitting on a local disk so that it doesn't have to waste precious memory for hosting it. This, of course, creates a bit of a complication where one following the bootflow has to constantly be aware whether rootfs is on disk or in memory.

All the logic of locating the right boot artifacts can been seen in [grub.cfg](../pkg/eve/installer/grub.cfg) and [ipxe.cfg](../pkg/eve/installer/ipxe.efi.cfg). All the cpio artifacts are loaded together and contribute files to the initial initramfs filesystem that the kernel will see. All of this is pretty vanilla Linux kernel boot flow, except for:

* order of the cpio artifacts matters: if you have a file with the same name in two artifacts the actual content of that file will be taken from the later cpio artifact (think of it as kernel doing sequence of `cpio -i` operations with root filesystem as a target)
* if rootfs was loaded in memory it will also appear in the initramfs filesystem under the fixed name `/initrd.image`. This kind of a trick is pretty unique to EVE and it comes at a price of Linux kernel sticking ALL of the cpio bits into that file (artifacts #5-#7) not just rootfs image. Therefore we have to search for where rootfs image actually begins in that file to pass that offset to a `losetup`.

Finally, once all the required boot artifacts have been made available in the initial initramfs, EVE leverages Alpine's ability to create an overlayfs-based stacked rootfilesystem by specifying [overlaytmpfs kernel option](https://gitlab.alpinelinux.org/alpine/mkinitfs/-/blob/master/initramfs-init.in) (look for `KOPT_overlaytmpfs` in the initramfs-init.in source to understand how it works). This is how EVE tweaks the content of the final rootfs to have additional files (e.g. the content of the installer container image appearing under `/containers/onboot/003-installer`).

## Booting under UEFI firmware

UEFI firmware mandates that a bootloader is always located on a special partition labeled `EFI System`.
This partition is expected to be formatted as a FAT filesystem and keep a binary file called BOOTX64.EFI
or BOOTAA64.EFI under the EFI/BOOT folder. EVE uses GRUB UEFI payload (build as part of the [grub](../pkg/grub))
package to create EFI/BOOT/BOOTX64.EFI or EFI/BOOT/BOOTAA64.EFI and provide GRUB with the initial
[configuration](../pkg/mkimage-raw-efi/grub.cfg.in) aimed at locating a 2nd stage of the GRUB bootloader
in IMGA or IMGB partitions. That 2nd stage GRUB is also expected to be a UEFI payload residing in a folder
named EFI/BOOT (although this time the folder is part of EVE's IMGA or IMGB filesystem which is typically
squashfs). Next to that 2nd stage GRUB is its own [configuration](../pkg/grub/rootfs.cfg) that is much
more complex and is tasked with figuring out how to load appropriate hypervisor and control domain kernels
(if needed).

After 1st stage GRUB determines which partition is active (IMGA or IMGB) it chainloads the 2nd stage GRUB.
This chainloading is done through the mechanism that is specific to UEFI payloads and is different from
legacy PC bootloader chainloading (read: don't try to chainload UEFI from legacy and vice versa).

Comparing the two configurations for the 1st stage and 2nd stage GRUB bootloaders will provide a clue
as to why there are two stages to begin with. Since the 1st stage GRUB is *the only* component in the
EVE stack that can *not* be upgraded after EVE gets deployed we want to keep it as simple as possible.
In fact, its job is so simple that its configuration file can be interpreted by a rescue shell parser
in GRUB and not a full normal mode (this is important because rescue shell parser, despite what its
[documentation says](https://www.gnu.org/software/grub/manual/grub/grub.html#Embedded-configuration)
[doesn't support](https://lists.gnu.org/archive/html/grub-devel/2015-10/msg00035.html) any kind of
conditional or looping statements).

Second stage GRUB is expected to do all the [heavy lifting](../pkg/grub/rootfs.cfg) of actually booting
an EVE instance and because it resides in IMGA or IMGB partitions it can easily be upgraded and patched.
Behavior of this stage of boot process is controlled by a read-only grub.cfg under {IMGA,IMGB}/EFI/BOOT/
but it can further be tweaked by the grub.cfg overrides on the CONFIG partition. Note that an override
grub.cfg is expected to be a [complete override](../pkg/grub/rootfs.cfg#L143) and anyone constructing
its content is expected to be familiar with the overall flow of read-only grub.cfg.

Options to use in grub.cfg on the CONFIG partition are defined below. Most options may be defined in the format
`set_global GRUB_VARIABLE "OPTION1=VAL1 OPTION2"` or appended to the value of variable with
`set_global GRUB_VARIABLE "$GRUB_VARIABLE OPTION1=VAL1 OPTION2"`. Please make sure that you understand the effect
of these options, they may affect the device operability. Adding/editing options in grub.cfg might make the device
fail to boot where the only possible recovery is to have a keyboard and screen to manually override incorrect settings
in grub.cfg with graphical GRUB menu to get the device to boot again.

1. Cgroup related options. Please follow the [example](README.md#eve-cgroups) to write
   these values in the correct GRUB variables:
    1. `dom0_mem` option of `hv_dom0_mem_settings` variable - memory limit for eve cgroup
       (default is `set_global hv_dom0_mem_settings "dom0_mem=800M,max:800M"`)
    2. `dom0_max_vcpus` option of `hv_dom0_cpu_settings` variable - cpu limit for eve cgroup
       (default is `set_global hv_dom0_cpu_settings "dom0_max_vcpus=1"`)
    3. `eve_mem` - memory limit for cgroups with services of EVE
       (default is `set_global hv_eve_mem_settings "eve_mem=650M,max:650M"`)
    4. `eve_max_vcpus` option of `hv_eve_mem_settings` variable - cpu limit for cgroups with services of EVE
       (default is `set_global hv_eve_cpu_settings "eve_max_vcpus=1""`)
    5. `ctrd_mem` option of `hv_ctrd_mem_settings` variable - memory limit for cgroups with containerd-shims of EVE
       (default is `set_global hv_ctrd_mem_settings "ctrd_mem=400M,max:400M"`)
    6. `ctrd_max_vcpus` option of `hv_ctrd_cpu_settings` variable - cpu limit for cgroups with containerd-shims of EVE
       (default is `set_global hv_ctrd_cpu_settings "ctrd_max_vcpus=1"`)
2. Installer options. These options are used during [the installation](DEPLOYMENT.md) process and may be set by adding
   them to `dom0_extra_args` grub variable with line
   `set_global dom0_extra_args "$dom0_extra_args OPTION1=VAL1 OPTION2 "`, where OPTION fields described below
   (`DISK` below is e.g. `sda`):
    1. `eve_blackbox` - if set, installer will collect [information](../pkg/mkimage-raw-efi/install#L93)
       from EVE to INVENTORY partition on installation media (it must be writable, i.e. USB flash drive)
       and exit without installation. It is disabled by default because this action may take a lot of time.
       May be selected from graphical GRUB menu.
    2. `eve_nuke_disks=DISK` - clean partition table on the defined disks before install.
       You can use multiple disks separated by comma. Please use this option if you know that other
       disks contain old EVE installations to clean them out.
    3. `eve_install_disk=DISK` - set particular disk to install EVE. Default behavior is to use any free disk found.
    4. `eve_persist_disk=DISK` - set particular disk to use for persistent data (volumes, logs, etc.).
       Default behavior is to use partition on the disk selected or defined for EVE installation.
    5. `eve_install_server=SERVER` - override `/config/server` with value defined in `SERVER`. Default behavior is to
       use server defined during building of installer media (e.g. `zedcloud.zededa.net` for releases).
    6. `eve_pause_before_install` - return to shell before installation and wait for `exit`. May be selected from graphical GRUB menu.
    7. `eve_pause_after_install` - return to shell after installation and wait for `exit`. May be selected from graphical GRUB menu.
    8. `eve_reboot_after_install` - reboot after installation complete, default behavior for IPXE.
       If not set, will poweroff device after installation. May be selected from graphical GRUB menu.
    9. `eve_install_skip_config` - do not install config partition onto device. May be selected from graphical GRUB menu.
    10. `eve_install_skip_persist` - do not install persist partition onto device. May be selected from graphical GRUB menu.
    11. `eve_install_skip_rootfs` - do not install rootfs partition onto device. May be selected from graphical GRUB menu.
    12. `eve_install_skip_zfs_checks` - install zfs by skipping minimum requirement checks.
    13. `eve_install_zfs_with_raid_level` - Sets raid level for zfs storage. Valid values are none,raid1,raid5,raid6. Default value is none.
       This option also applied for the first boot of a live image to prepare zfs persist pool instead of ext4.
3. General kernel parameters may be adjusted with `set_global dom0_extra_args "$dom0_extra_args OPTION1=VAL1 OPTION2 "`.
   They will be added to kernel cmdline.

## Booting under legacy PC BIOS (including virtualized environments using legacy PC BIOS)

The first problem presented by a legacy PC BIOS is that it doesn't understand GPT partitioned disks,
luckily GPT specification allows for a [Hybryd MBR/GPT](https://wiki.archlinux.org/index.php/Multiboot_USB_drive#Hybrid_UEFI_GPT_+_BIOS_GPT/MBR_boot)
scheme and we can use the MBR boot sector to bootstrap the entire sequence.

Thus, in addition to creating a UEFI compatible `EFI System` partition every disk with EVE also gets:

* an MBR boot sector with GRUB's [stage1 one bootblock code](https://thestarman.pcministry.com/asm/mbr/GRUB.htm)
* an MBR partition table (last 64 bytes of the MBR sector) with the following two partitions specified:
   1. Bootable MS DOS partition that points at exactly the same bytes on disk occupied by the content of `EFI System` partition
   2. [Protective MBR partition](https://www.rodsbooks.com/gdisk/hybrid.html)
* a stage2 GRUB bootloader embedded into the gap between the end of the GPT and the start of the `EFI System` partition (roughly 2Mb worth of space)

Note that when it comes to functionality the PC BIOS stage2 GRUB is identical to its UEFI payload sibling
from the previous section. Or to put it differently -- it is exactly the same source just built as a
stage1 i386 COM code as opposed to x86_64 UEFI payload code (just like you would build the same program
to run under two different operating systems).

Once those two parts are in place, a legacy PC BIOS looking at the very same GPT-partitioned disk, will
go through a very different boot sequence:

1. BIOS will recognize that the disk is MBR partitioned (it won't even notice a GPT partition table at all) and that the disk is bootable
2. Because the disk is bootable BIOS will load stage1 GRUB boot code from MBR block (just a single sector gets loaded)
3. stage1 boot code will read the first sector of stage2 GRUB from a statically pre-defined location on disk (see [deploy_legacy_grub](../pkg/mkimage-raw-efi/make-raw) for details)
4. the code from the first sector of stage2 (grub-core/boot/i386/pc/diskboot.S) will load up the rest of stage2 from a pre-defined location (see [deploy_legacy_grub](../pkg/mkimage-raw-efi/make-raw) for details)
5. stage2 GRUB will start by executing [embedded configuration file](../pkg/grub/embedded.cfg) script - this will set things up for serial console and also load up a normal configuration file from either IMGA or IMGB

You may notice that legacy GRUB is basically playing the role of the first GRUB instance in the UEFI booting sequence.
However, instead of chainloading the GRUB from IMGA/IMGB partition in the legacy BIOS boot case, we just start interpreting
the configuration file from IMGA/IMGB partition. This is done to simplify the initial implementation (you can't easily
chainload legacy GRUB images the way you can chainload UEFI payloads) but comes at a cost of NOT being able to upgrade
the GRUB code itself.

We fully intend to fix this by either implementing a custom chainloader for the legacy GRUB stored in the IMGA/IMGB
partition (next to UEFI GRUB under EFI/BOOT) or by embracing GRUB modules and loading the new GRUB module-by-module.

## Booting under Coreboot

Currently we simply leverage previous section through the use of [Coreboot SeaBIOS payload](https://www.coreboot.org/Payloads#SeaBIOS).
However, a project is in the works, to build our GRUB as a [native Coreboot payload](https://www.coreboot.org/Payloads#GRUB_2)
thus adding to the collection of GRUB binaries we need to maintain.

## Booting under board specific bootloader

ARM is notorious for mixing the concept of a firmware and a bootloader. While on x86 the firmware (with its responsibility
of initializing basic hardware such as RAM and CPU) is typically stored completely separately from bootloader in NVRAM,
on ARM it is fairly common to store firmware in the same flash driver that you would use for installing EVE and it is also
fairly common to build a single binary that does both: hardware initialization and all the booting.

This creates some truly interesting environments for EVE to boot under. For example, HiKey ARM boards are using a properly
structured GPT partitioned disk to store its firmware. This means that EVE can't really own the GPT and it has to add itself
to and already existing GPT structure hijacking the partition table IDs starting from 10 (or to put it differently -- what
would've been partition entry #1 on x86 becomes partition entry #11 on HiKey).

The upside of HiKey, of course, is that EVE at least doesn't have to worry about all the firmware bits -- as long as it
plays nice with HiKey's already pre-created GPT structure it simply expects HiKey's firmware to, ultimately, load up a
proper UEFI environment and call EVE's GRUB UEFI payload as it would happen normally. As such, HiKey presents a somewhat
hybrid environment where as long as we're careful with GPT -- we can simply re-use our default booting scheme with UEFI.

A popular Raspberry Pi ARM board, presents an extra challenge compared to HiKey. Just like HiKey it expects its firmware
to be stored on disk, but it also expects that disk to be partitioned with legacy MBR and it has fairly strict requirements
about how the first MBR partition needs to look like in order for Raspberry Pi to be able to load its firmware. This forces
EVE to use hybrid MBR/GPT partitioning scheme and advertise the `EFI System` partition as the first MBR partition visible
to Raspberry Pi (note that strictly speaking this goes against best practices of how protective MBR should looks like,
since the recommendation is for the first MBR partition to always be of the type protective MBR). Fortunately, at least
both UEFI and Raspbery Pi agree on the filesystem for the first partition: FAT.

To put it all together, for Raspberry Pi we use `EFI System` AKA MBR #1 partition to store the following artifacts (in addition
to EFI/BOOT folder):

* `fixup4.dat` and `start4.elf` files - these are opaque binary blobls that contain initial Raspberry Pi firmware
* `config.txt` - a [configuration file](https://www.raspberrypi.org/documentation/configuration/config-txt/) that is specific to the implementation of fixup4.dat and start4.elf and is usef to instruct Raspberry Pi to load u-boot.bin as thought it was a Linux kernel (see below)
* `startup.nsh`, `u-boot.bin` and `bcm2711-rpi-4-b.dtb` - 3 files required to launch u-boot bootloader (tricking Raspberry Pi firmware into thinking it is a Linux kernel)

With these artifacts in place, both ARM boards we support go through the following boot sequence:

* board loads custom firmware blobs
* custom firmware blob loads either UEFI environment or u-boot
* UEFI GRUB payload gets loaded
* the rest of the sequence follows the [Booting under UEFI firmware](#booting-under-uefi-firmware) protocol

One final note on our use of u-boot: as was mentioned before, u-boot is commonly used on ARM to provide both firmware and bootloader
services (thus eliminating or at least subsuming the need for opaque binary blobs like `fixup4.dat` and `start4.elf`). We may, at some point,
decide to implement IMGA/IMGB partition selection directly in u-boot to support an ecosystem of various ARM boards directly. However,
up until this point, it seems that all the boards that are modern enough to support EVE's virtualization requirements are also modern
enough to support UEFI environment directly (even for HiKey where we're currently using u-boot as a stop gap measure the proper
[UEFI implementation](https://github.com/pftf/RPi4) is very much in the works).

## Booting Raspberry Pi with netboot

### Boot flow

* board loads custom firmware blobs and `config.txt` from [tftp](#load-u-boot-with-netboot-on-raspberry-pi) or
  from [usb](#load-u-boot-from-usb). Inside `config.txt` we define `u-boot.bin` as kernel, so, board loads it from
  [tftp](#load-u-boot-with-netboot-on-raspberry-pi) or from [usb](#load-u-boot-from-usb).
* u-boot loads `boot.scr.uimg` via tftp which fires script inside (load `ipxe.efi` from tftp and run `bootefi`)
* ipxe requests dhcp option [67 Bootfile-Name](https://tools.ietf.org/html/rfc2132#section-9.5) which should point to
  `ipxe.efi`(actually, it will use configuration from `ipxe.efi.cfg` located on tftp).
* ipxe reads `ipxe.efi.cfg` and boots `kernel`, `initrd.img` and `initrd.bits` from locations defined inside `ipxe.efi.cfg`

#### Load u-boot from usb

You can load u-boot from usb. You should create FAT32 partition on your usb and put `overlays` directory, `u-boot.bin`,
`bcm2711-rpi-4-b.dtb`, `config.txt`, `fixup4.dat` and `start4.elf` on it.

#### Load u-boot with netboot on Raspberry Pi

In order to boot u-boot from tftp, you should modify bootloader configuration as
described [here](https://www.raspberrypi.org/documentation/hardware/raspberrypi/bcm2711_bootloader_config.md).
You should modify BOOT_ORDER to one that uses NETWORK mode (for example `0xf121`):

```shell
RPI_EEPROM_VERSION=pieeprom-2021-01-16
wget https://github.com/raspberrypi/rpi-eeprom/raw/master/firmware/beta/${RPI_EEPROM_VERSION}.bin
sudo apt update
sudo apt install rpi-eeprom -y
sudo rpi-eeprom-config ${RPI_EEPROM_VERSION}.bin > bootconf.txt
sed -i 's/BOOT_ORDER=.*/BOOT_ORDER=0xf241/g' bootconf.txt
sudo rpi-eeprom-config --out ${RPI_EEPROM_VERSION}-netboot.bin --config bootconf.txt ${RPI_EEPROM_VERSION}.bin
sudo rpi-eeprom-update -d -f ./${RPI_EEPROM_VERSION}-netboot.bin
```

### Files to load into tftp/http

You need to extract needed files with something like `docker run lfedge/eve:latest-arm64 installer_net |tar xf -`.
You will see a set of files in the current directory to locate into you tftp server to boot Raspberry from it. Also, you should set dhcp-boot option of your
dhcp server to `ipxe.efi` (actually, it will use configuration from `ipxe.efi.cfg`). Files `kernel`, `initrd.img` and `initrd.bits`
should be available via HTTP/HTTPs and you need to modify `ipxe.efi.cfg` with location of those files.
