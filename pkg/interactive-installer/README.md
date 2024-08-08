# EVE-OS interactive installer

## Description

The EVE-OS interactive installer provides a user-friendly text-based user interface (TUI) to configure the parameters of the installation. Utilizing a TUI, allows users to configure installation parameters with ease. The primary goal of this installer is to simplify the installation process on edge devices while offering flexibility and automation, similar to the installation wizards used for setting up new Wi-Fi routers.

## Configuration steps

Users can configure the installation parameters through a series of steps, with the ability to navigate back and forth until their choices are finalized. The steps are as follows:

1. Choose Filesystem Type: Select from options such as squashfs, EXT3, EXT4, and ZFS.
2. Choose RAID Option: If ZFS is selected, choose whether to enable RAID.
3. Choose Installation Disk: Select the disk where EVE-OS will be installed.
4. Choose Persist Disk: Select the disk for the persistent partition.
5. Choose Additional Configuration Options: Customize additional settings as needed.
6. Overview: Review all selected options before finalizing the installation.

## Implementation

The interactive installer is introduced as a new container that precedes the storage-init container. The codebase is primarily written in Rust. This container is included in the normal boot sequence of EVE-OS.

### How It Works

* Boot Sequence: During the boot sequence, users can select a new GRUB option for the interactive installer, alongside the normal installer.
* GRUB Option: Selecting the interactive installation option appends the string "interactive" to /proc/cmdline, distinguishing it from the normal installation.
* Configuration File: Once the user has finalized their configuration, it is saved in a JSON file, which the system uses to perform the actual installation.

By following these steps, the EVE-OS interactive installer streamlines the installation process, making it accessible and customizable for users deploying EVE-OS on edge devices.
