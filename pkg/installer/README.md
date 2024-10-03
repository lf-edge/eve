# Installer Image

This is the image for installing EVE on a device and then optionally verifying the installation.
It is intended to be run when an EVE image boots.

The installer itself is a lightweight image, containing the necessary utilities, and an install script. The install script
leverages utilities from other parts of EVE.

It is expected to be run as a standalone container, as an `onboot` service in EVE, see the installer OS build
image [yaml file](../../images/installer.yml.in).

The install can be controlled via various cmdline flags.

The installer can be set to debug mode running it via one of:

* environment variable `DEBUG=1`
* kernel cmdline flag `eve_install_debug`

This expects to be run with full capabilities, and the following mounts, set in [build.yml](./build.yml):

```yaml
    - /dev:/dev
    - /lib/modules:/lib/modules
    - /run:/run
    - /:/root
```

In addition, it expects to have the following:

* `mkimage-raw-efi` image available read-only at `/mkimage`. This is set in the [installer.yml](../../images/installer.yml.in) file. It uses it to launch `make-raw`, in order to write to the target installation disk.
* `/bits/rootfs.img` - the rootfs image to install. This is set in the [installer.yml](../../images/installer.yml.in) file.
* `/bits/persist.img` - the persist image to install. This is set in the [installer.yml](../../images/installer.yml.in) file.

## Installer interactive mode

### Description

The interactive mode of installer provides a user-friendly text-based user interface (TUI) to configure the parameters of the installation. Utilizing a TUI, allows users to configure installation parameters with ease. The primary goal of this installer is to simplify the installation process on edge devices while offering flexibility and automation, similar to the installation wizards used for setting up new Wi-Fi routers.

### Configuration steps

Users can configure the installation parameters through a series of steps, with the ability to navigate back and forth until their choices are finalized. The steps are as follows:

1. Choose Installation Disk: Select the disk where EVE-OS will be installed.
2. Choose Filesystem Type: Select either EXT4 or ZFS for persist partition.
3. Choose RAID Option: If ZFS is selected, choose whether to enable RAID with available modes: RAID1, RAID5, RAID6.
4. Choose Persist Disks: Select the disks for the persistent partition.
5. Choose Additional Configuration Options: Customize additional settings as needed.
6. Overview: Review all selected options before finalizing the installation.

### Implementation

The interactive installer is introduced as a new container that precedes the storage-init container. The codebase is primarily written in Rust. This container is included in the normal boot sequence of EVE-OS.

### How It Works

* Boot Sequence: During the boot sequence, users can select a new GRUB option for the interactive installer, alongside the normal installer.
* GRUB Option: Selecting the interactive installation option appends the string "interactive" to /proc/cmdline, distinguishing it from the normal installation.
* Configuration File: Once the user has finalized their configuration, it is saved in a JSON file, which the system uses to perform the actual installation.

### Updating the vendors

When changing the code, we might need to add or update the libraries we use. To update the vendors we need to install rust and cargo,
and run the following command:

```bash
cargo vendor
```
