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

It is not clear why this cannot be replaced with `linuxkit build -o raw-efi` or `linuxkit build -o kernel+squashfs`. The missing elements are listed here:

* 


### makeflash

[makeflash.sh](../makeflash.sh) is a script that creates an empty file of the target disk image size. This target is then passed to [mkimage-raw-efi](../pkg/mkimage-raw-efi), which partitions the provided disk image into the requested partitions, and installs the correct bits in each partition: grub into `efi`, a pre-built rootfs into `imga` and optionally `imgb`, a pre-built config into `config`. 

There is no tool that currently does anything close to this. The closest option might be linuxkit, if it were to add support for multiple partitions, with optional inputs into each partition.

### maketestconfig

[maketestconfig.sh](../maketestconfig.sh) is a script that tars up the contents of [conf/](../conf/), passing the tar stream to [mkconf](../pkg/mkconf), which lays those contents on top of the contents of `/opt/zededa/examples/config` from [ztools](https://github.com/zededa/go-provision) and puts the result in a FAT32 image named `config.img`. 

This is a fairly straightforward process - somewhat complicated by the two layers of tarring the local directory up and then overwriting the `ztools` default in a separate container, but not unduly so - and is unlikely to be replaced by any other tool. At best, in its current usage, it can be simplified somewhat as a single container image run.

More relevant and useful is an analysis of the usage of `config` in a production-quality system. It is unlikely that the fixed config in `/opt/zededa/examples/config` or `conf/`, as described by the installer name `maketestconfig.sh` (with the word `test`), will be used in production-scale deployments. We should determine how we want to use `config` in real deployed systems, how it will be installed, where it applies to the device API protocol, and design a full solution.

## Components

### grub

[grub](pkg/grub) applies a series of necessary patches to [upstream grub](https://www.gnu.org/software/grub/). These patches are in [pkg/grub/patches](../pkg/grub/patches). The primary way to eliminate the need for custom grub is to upstream these patches into grub itself. The largest of them - the [coreos patches](../pkg/grub/patches/0000-core-os-merge.patch) is in the process of being upstreamed, courtesy of Matthew Garrett, who did the original work at CoreOS and is now at Google. The rest simply require effort to interact with the main grub team and get the patches accepted.

The customizations we apply via patches, and their purpose (i.e. we why need them for EVE), are as follows:

#### 0000-core-os-merge.patch

Merge in all of the changes that the CoreOS (RIP, CoreOS Inc) team included in their [fork of grub](https://github.com/coreos/grub). These include the following, and why we need them:

* PLEASE FILL IN

#### 0001-TPM-build-issue-fixing.patch

Apparently, there is build issue which mainstream grub (or possibly just coreos's version) has when building the tpm support. This fixes it in both `tpm.h` and `tpm.c`. The patch was submitted via staff at ARM in August 2017, so it is unclear if this is an issue _just_ on arm architectures, or a general problem. Additionally, even though tpm support was added (at least for efi booting) in mainstream grub as of late December 2018 into early 2019, `tpm.c` does not exist in the given location, and may be elsewhere. This entire patch may or may not be necessary.

#### 0002-video-Allow-to-set-pure-text-mode-in-case-of-EFI.patch

Mainstream grub's loader for `i386/linux`, when EFI is defined via `define GRUB_MACHINE_EFI`, does not accept pure text mode. This leads to the common, "no suitable video mode found" error. This patch fixes it by defining `define ACCEPTS_PURE_TEXT 1` in EFI.

It is unclear _why_ mainstream grub does not accept pure text mode, and should be investigated.

#### 0003-allow-probe-partuuid.patch

Mainstream grub's does not enable searching for partitions via the partition's UUID. It does for filesystem elements, including its label and UUID, but not the partition's. This adds support for searching via partition UUID.

#### 0004-Disabling-linuxefi-after-the-merge.patch

This disables and removes the `linuxefi` command that the coreos grub patch added.

It is unclear _why_ we need to remove this. The original purpose of the `linuxefi` option, added [here](https://github.com/coreos/grub/pull/4) appears to be to handle shims for secure boot, but may have other usages. 

#### 0005-rc-may-be-used-uninitialized.patch

In the function `grub_install_remove_efi_entries_by_distributor`, sets the default of `int rc = 0`, so it never is accessed uninitialized. 

**Note:** this has been fixed in mainstream grub as of master on the date of this writing, see [grub-core/osdep/unix/platform.c#L88](http://git.savannah.gnu.org/cgit/grub.git/tree/grub-core/osdep/unix/platform.c#n88). If we update to a more recent commit, we can remove this patch, assuming, of course, that a previous patch does not break it, likely the coreos one.

#### 0006-export-vars.patch

Exports current grub setting vars. Need and usage is unclear.


### devices-trees

[devices-trees](pkg/devices-trees/) adds specific device tree source files and compiles them. This is unlikely to be upstreamed anywhere, but may be extractable. This is likely to be a primary place for extensibility.

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

* `sgdisk` - with specific patches listed [here](../pkg/gpt-tools/patches)
* `cgpt` - works with ChromeOS-specific GPT partitioning
* [zboot](../pkg/gpt-tools/files/zboot) - a script whose purpose is unknown. It is not referenced elsewhere that we can find.

Upstreaming may be possible with `sgdisk`, if the patches are included. 

### dom0-ztools

[dom0-ztools](../pkg/dom0-ztools) inserts a single script, [zen](../pkg/dom0-ztools/zen) onto the base filesystem. `zen` is a utility script that wraps `ctr` to simplify access to containerd containers. This presumably is because the `ctr` commands can be convoluted and hard to remember.

There is a case to be made for upstreaming this into linuxkit itself, at least in the ssh/getty containers.




