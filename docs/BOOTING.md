# Booting EVE

Everytime an Edge Node running EVE is powered on or rebooted, the first piece of software
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
grub.cfg is expected to be a [complete override](../pkg/grub/rootfs.cfg#L132) and anyone constructing
its content is expected to be familiar with the overall flow of read-only grub.cfg.

## Booting under legacy PC BIOS (including virtualized environments using legacy PC BIOS)

The first problem presented by a legacy PC BIOS is that it doesn't understand GPT partitioned disks,
luckily GPT specification allows for a [Hybryd MBR/GPT](https://wiki.archlinux.org/index.php/Multiboot_USB_drive#Hybrid_UEFI_GPT_+_BIOS_GPT/MBR_boot)
scheme and we can use the MBR boot sector to boostrap the entire sequence.

Thus, in addition to creating a UEFI compatible `EFI System` partition every disk with EVE also gets:

* an MBR boot sector with GRUB's [stage1 one bootblock code](https://thestarman.pcministry.com/asm/mbr/GRUB.htm)
* an MBR parition table (last 64 bytes of the MBR sector) with the following two partitions specified:
   1. Bootable MS DOS parition that points at exactly the same bytes on disk occupied by the content of `EFI System` partition
   2. [Protective MBR partition](https://www.rodsbooks.com/gdisk/hybrid.html)
* a stage2 GRUB bootloader embedded into the gap between the end of the GPT and the start of the `EFI System` parition (roughly 2Mb worth of space)

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
However, instead of chainloading the GRUB from IMGA/IMGB parition in the legacy BIOS boot case, we just start interpreting
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
proper UEFI environment and call EVE's GRUB UEFI payload as it would happen normaly. As such, HiKey presents a somewhat
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
decide to implement IMGA/IMGB parition selection directly in u-boot to support an ecosystem of various ARM boards directly. However,
up until this point, it seems that all the boards that are modern enough to support EVE's virtualization requirements are also modern
enough to support UEFI environment directly (even for HiKey where we're currently using u-boot as a stop gap measure the proper
[UEFI implementation](https://github.com/pftf/RPi4) is very much in the works).
