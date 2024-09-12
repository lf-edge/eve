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
