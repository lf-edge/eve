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

[grub](../pkg/grub) applies a series of necessary patches to [upstream grub](https://www.gnu.org/software/grub/). These patches are in [pkg/grub/patches-2.06](../pkg/grub/patches-2.06). We use several patches adopted from [grub2 2.06-2ubuntu7](https://launchpad.net/ubuntu/+source/grub2/2.06-2ubuntu7) in [0001-adopted](../pkg/grub/patches-2.06/0001-adopted) and our own patches in [0002-own](../pkg/grub/patches-2.06/0002-own).

For upstreaming, we should:

1. See if there is an easier or more canonical way to do the same thing without a custom patch. If so, use it.
2. If not, present the use case to grub upstream and get the patch upstreamed.

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

* `sgdisk` - with specific patches listed [here](../pkg/gpt-tools/patches)
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
