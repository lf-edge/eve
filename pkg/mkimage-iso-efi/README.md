# mkimage-iso-efi

Take the entire contents of a directory or tar stream and create an ISO image that can be booted on a
device running UEFI.

In addition, the following will be created:

1. An El Torito compliant FAT32 image that can be booted by UEFI firmware.
1. An `initrd.img` that can be used to boot the kernel and mount the ISO filesystem.

The `initrd.img` will be for the architecture of the input filesystem tar stream. All executables placed in the initrd, if
needed, will be taken from the tar.

## Usage

### Input

The input contents can be either a tar stream or a directory.

From tar stream, feed it to the container as stdin. Don't forget to pass `-i` to `docker run`.

```sh
cat tarfile.tar | docker run -i --rm -v $(pwd)/target.iso:/output.iso lfedge/eve-mkimage-iso-efi
```

From directory, mount the input directory to `/bits`.

```sh
docker run --rm -v /path/to/input:/bits -v $(pwd)/target.iso:/output.iso lfedge/eve-mkimage-iso-efi /path/to/directory
```

### Output

ISO is saved into the file `/output.iso` inside the container. If you want it available outside
the container, you must volume-mount a file to `/output.iso`.

```sh
docker run --rm -v $(pwd)/target.iso:/output.iso lfedge/eve-mkimage-iso-efi /path/to/directory
```

### ISO Volume Label

You can control the volume label of the image by passing the environment variable `VOLUME_LABEL`.
For example:

```sh
docker run --rm -e VOLUME_LABEL=MYISOVOL -v $(pwd)/target.iso:/output.iso lfedge/eve-mkimage-iso-efi /path/to/directory
```

## Components

### El Torito boot image

The El Torito complaint FAT32 image `boot.img` is created that can be booted by UEFI firmware, and contains the contents of `EFI/` from the input. The `boot.img` is hidden from the directory listing, and made available via the El Torito `boot.catalog`.

The `boot.img` is configured to just boot the file `/EFI/BOOT/grub.cfg` from the main ISO
filesystem, so put anything you care about there. This image builder does not do anything with you
`grub.cfg`; it is up to you to create it as you will.

### Initrd

If no `/boot/initrd.img` is in the filesystem, it will be created. It is a simple initramfs that
only knows how to find the value of cmdline `root=` and mount it for the kernel, and launch init from it
as the root of the filesystem.

```sh
exec switch_root /mnt /sbin/init
```

Most of what it does, the kernel already knows how to do. In a few areas, however, the kernel
does not know how to handle things. For example, labels for CD/ISO9660 filesystems are not
recognized.

## How to boot the ISO image

1. Boot on a device with EFI firmware; do not try it on non-EFI.
1. Set `initrd` and `root` to appropriate settings in your grub.cfg. Here are the options:

### You already have an initrd.img in your directory or tar stream

Do nothing. This builder will not overwrite your `/boot/initrd.img`.

In your `grub.cfg`:

1. Set `initrd /boot/initrd.img`, which will tell the kernel to load and run the `initrd.img` as its initial ram filesystem.
1. Set the kernel cmdline `root=` to whatever you want.

### You have no initrd.img, and expect the device to boot from a known device

In your `grub.cfg`:

1. Set `initrd /boot/initrd.img`
1. Set the kernel cmdline `root=` to the specific boot device, e.g. `/dev/sr0` or `/dev/sda1`.

### You have no initrd.img, and expect the device to boot from a known label

For example, you expect your CD to have the label `MYLABEL`. You might not be sure
which device it will be, e.g. `sr0` or `sr1`.

1. Set `initrd /boot/initrd.img`
1. Set the kernel cmdline `root=LABEL=MYLABEL`

For example:

```grub
initrd /boot/initrd.img root="LABEL=MYLABEL"
```

The initrd.img will be created by this installer, and knows how to find the `root=` and mount it.

## Known root flags

It accepts the following `isoroot=` flags:

* `LABEL=` - filesystem label including iso9660
* `PARTLABEL=` - GPT partition label
* `UUID=` - filesystem UUID
* `PARTUUID=` - GPT partition UUID
* `*` - anything else is a device path, or even a file path, e.g. `/dev/sr0` or `/installer.iso`
