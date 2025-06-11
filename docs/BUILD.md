# Building EVE

This document describes how the EVE build process works, its dependencies, inputs and outputs. The planned complementary document [CONTRIBUTING.md](../CONTRIBUTING.md) describes how to contribute to EVE.

If you want to customize any part of the build for your own purposes, to generate a custom eve-os image, please read this document to understand it,
and then read [CUSTOM-BUILD.md](./CUSTOM-BUILD.md).

## Conceptual structure of EVE Makefile targets

EVE Makefile automates building and running the following artifacts (all of which are described in gory details below):

* OCI images, which are the "building blocks" composed together into the EVE rootfs; these are linuxkit packages, in [pkg/](../pkg/), build via `linuxkit pkg build`
* EVE rootfs images
* bootable EVE live images
* bootable EVE installer images

![Build Process](./images/build-process.png)

While the packages don't provide any knobs to control the flavor of the build, the rest of the artifacts do.
These can be set as variables to `make` targets.

The main knobs that control the flavor of the build are the following. Each of these has reasonably sane
defaults, when possible.

| Variable | Description | Default | Examples |
| --- | --- | --- | --- |
| `ROOTFS_VERSION` | Version ID of the EVE image | calculated from the git commit | `snapshot`, `1.2.3-abcd567` |
| `ZARCH` | Hardware architecture of the resulting image | your current platform | `amd64`, `arm64`, `riscv64` |
| `HV` | Hypervisor flavor of the resulting image | `kvm` (amd64, arm64) or `mini` (riscv64) | `kvm`, `xen`, `acrn`, `mini`, `kubevirt` |
| `PLATFORM` | Specific platform for which to build | `generic` | `generic`, `rt`, `nvidia-jp6`, `imx8mp_pollux` |

Finally, the target determines what type of image you are building, e.g.`live`, `installer`.

As much as possible, incompatible combinations will be caught and prevent a build. For example,
`PLATFORM=nvidia-jp6` is for the ARM-based Jetsons, so `ZARCH=amd64` is incompatible and will be caught.

You can specify an arbitrary combinations of these knobs to set the desired outcome of the build.

For example, the following command line will build a generic qcow2 live image with the default
hypervisor set to `kvm`, hardware architecture set to `amd64` and the version ID set to `snapshot`:

```shell
make ROOTFS_VERSION=snapshot ZARCH=amd64 HV=kvm live
```

To build the same image but for Google Compute Platform (notice the different target):

```shell
make ROOTFS_VERSION=snapshot ZARCH=amd64 HV=kvm live-gcp
```

Same way, since HV applies at
the rootfs level (rootfs binary is then fed wholesale into live and installer builds) you can build
a `snapshot` rootfs with the hypervisor set to acrn by doing either:

```shell
make ROOTFS_VERSION=snapshot HV=acrn rootfs
```

or

```shell
make ROOTFS_VERSION=snapshot rootfs-acrn
```

In this hierarchy, think of `ZARCH` and `ROOTFS_VERSION` as applicable to anything hence they don't get a -foo shortcut treatment.

When in doubt, always use a full specification on all the knobs via variables spelled out on the command line.

## EVE Install Methods

Before describing how EVE is _built_, it is important to understand how EVE is _installed_. EVE has two distinct installation methods:

* Installing a Live Image
* Using an Installer Image

### Installing a Live Image

A live image is ready for an actual device. It is flashed directly to a USB drive or SD card, which is then installed into a final device. As such, the live image has all of the necessary partitions, and is not expected to boot anything but a live device.

### Using an Installer Image

An installer image is intended to be booted on multiple devices, each time installing a live image onto the local device. It is flashed to a USB drive or SD card. The card is then installed into a device, the device is booted, the installer installs a live image onto the device's actual long-term storage, and then the install media is disconnected and moved to the next device to repeat the process.

Since an installer is many-use, potentially across many sites, the small amount of configuration may need to change between sets of installs. The installer image can have its configuration changed between installs by connecting it to a live running system.

## Dependencies

EVE uses several build tools, some of which are prerequisites, while others are installed as needed.

### Prerequisites

You must have the following installed in order to build EVE:

* [docker](https://www.docker.com/get-started)
  * [buildx](https://docs.docker.com/reference/cli/docker/buildx/)
* [Go](https://golang.org) (optional) Required only if you want to build packages locally. By default, all builds happen in a docker environment.
* [qemu](https://www.qemu.org) (optional) Required only if you wish to run the generated image. On macOS, easiest to install via [homebrew](https://brew.sh) via `brew install qemu`.
* [git](https://git-scm.com) which you must have to clone this repository.
* [swtpm](https://github.com/stefanberger/swtpm) (optional) Required only if you wish to run EVE-OS in qemu with TPM device. On macOS, easiest to install via [homebrew](https://brew.sh) via `brew install swtpm`. On Ubuntu with enabled apparmor please disable apparmor for swtpm after install to use it from local directory: `sudo ln -s /etc/apparmor.d/usr.bin.swtpm /etc/apparmor.d/disable/ && sudo apparmor_parser -R /etc/apparmor.d/disable/usr.bin.swtpm`.

### Installed As Needed

* [linuxkit](https://github.com/linuxkit/linuxkit) - CLI used to build actual EVE bootable images.

Each "Installed as Needed" build tool will place its final executable in `${GOPATH}/bin/`, e.g. `~/go/bin/linuxkit`.

To build a specific tool, you can execute `make build-tools/bin/<tool-name>`, e.g. `make build-tools/bin/bin/linuxkit`.

This target does the following:

1. Create a temporary directory
1. Initialize git in that directory
1. Fetch just the target commit to the directory
1. Install tools as needed
1. Remove the temporary directory

To build all of the tools, in the project root directory, run `make build-tools`

#### Reasoning

The normal process for installing go-based binaries is to execute `go get` with options, e.g.

```shell
go get -u github.com/linuxkit/linuxkit/src/cmd/linuxkit
go get -u github.com/estesp/manifest-tool
```

EVE uses a somewhat non-standard build process for these tools to ensure
specific versions without polluting the user's normal workspace.

## Output Components

The following are the output components from the build process and their purpose. There are two kinds of components: final, generally intended for actual direct usage, and interim, used to build the final components. Some interim components may be removed as part of the build finalization process.

However, **every** build of an EVE image will create `rootfs.tar`, whether on the way to various
live or installer image formats, or useful by itself. This tarfile contains the root filesystem, whose
contents then may be used to generate the final versions: live vs installer, qcow2 vs raw vs GCP, etc,
or may be useful on its own.

The important work in generating EVE is primarily in creating `rootfs.tar`. All of the rest is:

* converting formats and tools to do so
* packaging
* additional metadata such as SBoMs

### Final

* `rootfs-VERSION.IMG_FORMAT` - a live bootable rootfs filesystem image. This can be either [squashfs](https://en.wikipedia.org/wiki/SquashFS) (default) or [ext4](https://en.wikipedia.org/wiki/Ext4).
* `rootfs.img` - a symlink to the actual, versioned rootfs image file that was built last
* `live.raw` - a final bootable live disk image in raw format with only few key partitions created (the rest will be created on first boot):
    1. UEFI partition with grub
    2. config partition with the content of `config.img` described below
    3. root partition from the above `rootfs.img`
* `live.qcow2` - the final bootable live disk image in [qcow2](https://en.wikipedia.org/wiki/Qcow) format
* `live.vdi` - the final bootable live disk image in vdi format (used in VirtualBox systems)
* `live.parallels` - the final bootable live virtual hard disk image in Parallels format
* `live.img.tar.gz` - the final bootable live disk image in [Google Compute Platform](https://cloud.google.com/compute/docs/import/import-existing-image) format
* `live.img` - a symlink to one of the above images that was built last
* `installer.raw` - a bootable image that can install EVE on a local device. The installer is intended to be flashed to a USB or SD device, or booted via PXE, and then run to install on a local drive.
* `installer.iso` - a bootable ISO image with a hidden EFI boot partition and an installer partition, with the contents of `installer.raw`. The installer is intended to be booted in a manner typical of iso files, and then run to install on a local drive.

### Interim

* `rootfs_installer.img` - a bootable rootfs filesystem image to run as an installer.
* `config.img` - 1MB FAT32 image file containing basic configuration information, including wpa supplicant, name of the controller, onboarding key/cert pair, and other configuration information.
* `rootfs.tar` - as described above.

## Build Process

The general rules for the build process are as follows.

All bootable images are built via [linuxkit](https://github.com/linuxkit/linuxkit), using standard linuxkit yml configuration files. Read documents at the [linuxkit repository](https://github.com/linuxkit/linuxkit) to learn more about how linuxkit works, composing OCI images to create a bootable disk.

EVE builds one of two bootable images using linuxkit, depending on if you are building an installer or a live image, and then modifies them with various tools.

### Live

For a live bootable image, named `live.img`, we create the following dependencies in order:

1. `rootfs.tar`
2. `rootfs.img`
3. `config.img`
4. `live.raw`
5. `live.qcow2`

#### `rootfs.tar`

This is the rootfs filesystem in a tar file.
It is a temporary artifact which is used as input into security and bill-of-materials scanners,
and is then consumed to create other artifacts, and then can be removed. To build it:

1. Verify the existence of the linuxkit builder configuration file `images/rootfs.yml`. See notes on [generating yml](#generating-yml) to understand how this is generated.
1. Call `makerootfs.sh tar -y images/rootfs.yml -t path/to/rootfs.tar [-a <arch>]`, which will build an image for the target architecture `<arch>` using `linuxkit` with a tar output format using `images/rootfs.yml` as the configuration file, saving the output to `path/to/rootfs.tar`.

When done with any later builds, you can remove the temporary artifact `path/to/rootfs.tar`.

When run with `make rootfstar` or `make rootfs.tar` or `make rootfs`, this will build the rootfs tar file:

* For the default architecture;
* Saving the tar file to `dist/<arch>/<path-from-commit-and-version-and-date>/`

#### rootfs.img

`rootfs.img` is a bootable root filesystem. To build it:

1. Verify the existence of the rootfs tar file from the previous stage.
1. Call `makerootfs.sh imagefromtar -i path/to/rootfs.img -t path/to/rootfs.tar -f <format>`, which will:
    1. Pipe the contents of the tar image to a docker container from either `mkrootfs-ext4` or `mkrootfs-squash`, depending on desired output format.
    2. `mkrootfs-*` takes the contents of the tar image, modifies `grub.cfg`, builds it into an ext4 filesystem image, and streams it to stdout.
    3. Direct the output to the targeted filename, in this case `path/to/rootfs.img`.

We now have `path/to/rootfs.img`.

If you will not need any of the interim steps, you can run `makerootfs.sh image -y images/rootfs.yml -f <format> -a <arch> -i path/to/rootfs.img`, which combines:

1. Creating the tar
1. Creating the disk image

#### config.img

`config.img` is a simple image containing the basic configurations necessary to run EVE. These files are intended to be on their own partition on the final image.

To build `config.img`:

1. Verify the existence of dependencies, essentially everything in `conf/`
2. Call the script to create the image: `./tools/makeconfig.sh config.img conf`. This will:
    1. tar up the contents of the config directory into a tar format.
    2. stream the contents of the tar format into a docker container from the image generated by `pkg/mkconf`. `mkconf` is an image that contains the `make-config` script and all of `/opt/zededa/examples/config` from [pillar](https://github.com/lf-edge/eve/pkg/pillar).
    3. `mkconf` creates a FAT32 image whose root is everything copied from pillar/conf overwritten by everything from `$PWD/conf/`.
    4. `mkconf` saves the image to `config.img`

#### live.raw

`live.raw` is a live bootable raw disk image with both a rootfs and a UEFI boot partition.

To build `live.raw`:

1. Ensure `rootfs.img` and `config.img` are ready.
2. tar these two dependencies together and stream to [makeflash.sh](../makeflash.sh)
3. Call `./makeflash.sh -C live.raw`
4. `makeflash.sh` creates an empty image of the target size at the target path, and then passes control to a docker container from the image generated by `pkg/mkimage-raw-efi`. It does _not_ pass on the names of the partitions to be created, depending on the default.
5. `mkimage-raw-efi`:
    0. Calculates required size of the resulting image if '-C' option is provided
    1. Extracts the contents of the tar stream to `/parts/`
    2. Creates a partition for each of `efi`, `imga`, `imgb`, `conf`, `persist`
    3. Populates each partition with its appropriate contents:
        * `efi`: contents of `/EFI/BOOT/` from `/parts/rootfs.img`
        * `imga`/`imgb`: contents of `/parts/rootfs.img`
        * `conf`: contents of `/parts/config.img` as a partition of type `13307e62-cd9c-4920-8f9b-91b45828b798`. This is a custom GUID for EVE configuration.
        * `persist`: contents of `/parts/persist.img` if it exists, else empty
    4. Populates the embedded boot partition with the grub `*.EFI` binary and `grub.cfg` file
    5. Validates the image.

#### live.qcow2

`live.qcow2` is the final version of the live bootable image, in qcow2 format.

To build `live.qcow2`:

1. Ensure that `live.raw` exists.
2. Convert it to `live.qcow2` via `qemu-img convert`
3. Remove `live.raw`

#### live.img

`live.img` is a convenience universal pointer to the final image.

To build `live.img`:

```shell
ln -s live.qcow2 live.img
```

### Installable

For an installable image, named `installer.img`, we create the following dependencies in order:

1. `rootfs.img`
2. `config.img`
3. `rootfs_installer.img`
4. `installer.raw`

#### Installer: rootfs.img

`rootfs.img` is built identically to how it is for a live bootable image, see [rootfs.img](#rootfsimg)

#### Installer: config.img

`config.img` is built identically to how it is for a live bootable image, see [config.img](#configimg)

#### Installer: rootfs_installer.img

`rootfs_installer.img` is the actual bootable image that installs EVE onto another storage medium, normally an on-board disk/ssd on a device.

To build `rootfs_installer.img`:

1. Ensure the existence of the prerequisites: `rootfs.img`, `config.img`, `images/installer.yml`. The `yml` file is the configuration file for using linuxkit to build the `rootfs_installer.img`. See notes on [generating yml](#generating-yml).
2. Call `makerootfs.sh images/installer.yml rootfs_installer.img <format> <arch>`, which will:
    1. Build an image for the target architecture `<arch>` using `linuxkit` with a tar output format using `images/installer.yml` as the configuration file..
    2. Pipe the contents of the tar image to a docker container from either `mkrootfs-ext4` or `mkrootfs-squash`, depending on desired output format.
    3. `mkrootfs-*` takes the contents of the tar image, modifies `grub.cfg`, builds it into an ext4 or squasfhs filesystem image, and streams it to stdout.
    4. Direct the output to the targeted filename, in this case `rootfs_installer.img`.

#### Installer: installer.raw

`installer.raw` is a bootable raw disk installer image with both a rootfs and a UEFI boot partition.

To build `installer.raw`:

1. Ensure `rootfs_installer.img` and `config.img` are ready.
2. tar these two dependencies together and stream to [makeflash.sh](../makeflash.sh)
3. Call `./makeflash.sh -C live.raw "efi imga conf_win"`
4. `makeflash.sh` creates an empty image of the target size at the target path, and then passes control to a docker container from the image generated by `pkg/mkimage-raw-efi`. It _does_ pass on the names of the partitions to be created, limiting it to `efi`, `imga`, `conf_win`. There is no need for `imgb` or `persist` partitions for an installer image that will not be persisting data, and will not be updating its root filesystem.
5. `mkimage-raw-efi`:
    0. Calculates required size of the resulting image if '-C' option is provided
    1. Extracts the contents of the tar stream to `/parts/`
    2. Creates a partition for each of `efi`, `imga`, `conf_win`
    3. Populates each partition with its appropriate contents:
        * `efi`: contents of `/EFI/BOOT/` from `/parts/rootfs.img`
        * `imga`: contents of `/parts/rootfs.img`
        * `conf_win`: contents of `/parts/config.img` as partition type `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`, or Windows Data partition. Other than the partition type, `conf_win` is identical to `conf`. This is required so that this partition can be mounted on MacOS and Windows machines for users to add/change configuration on an installer image in between installs.
        * `persist`: contents of `/parts/persist.img` if it exists, else empty
    4. Populates the embedded boot partition with the grub `*.EFI` binary and `grub.cfg` file
    5. Validates the image.

Note that once you flash `installer.raw` on the installer media, such as USB drive or SD card, since the `conf_win` partition is a Windows Data partition, most operating systems will recognize it and allow you to mount it. This allows you to update configuration on the installer media between installs.

## Generating yml

The core `rootfs.tar` or `installer.tar` files are generated using `linuxkit build`, which is driven by a `yml` file.
The `yml` file is in the `images/out` directory and is named `rootfs-$(HV)-$(PLATFORM)-<rootfs flavor>.yml`, where `HV` is the hypervisor,
e.g. `kvm`, `xen`, `acrn`, `mini`, `kubevirt`, and can be set in the environment variable `HV`, and `PLATFORM` is the platform, e.g. `generic`, `rt`, `nvidia-jp6`, `imx8mp_pollux`, etc. and can be set in the environment variable `PLATFORM`.
e.g. `make rootfs.tar HV=kvm PLATFORM=generic`.

Rootfs flavor is not currently used by any platform except for `evaluation`.

The actual `yml` file `images/out/rootfs-$(HV)-$(PLATFORM)-<rootfs flavor>.yml` is not checked into version control, nor is any file
in [images](../images/). Rather, the checked-in files in this directory are templates and modifiers:

* templates: `rootfs.yml.in`, `installer.yml.in` and `version.yml.in`
* modifiers are located in `images/modifiers` and structured as following:
  * `images/modifiers/hv/<HV>.yq` - hypervisor-specific modifiers
  * `images/modifiers/platform/<platform name>/` - platform-specific modifiers. A platform may require separate modifiers to be applied to `rootfs.yml.in` and `installer.yml.in`. In this case the platform-specific modifiers are located in `images/modifiers/platform/<platform name>/rootfs-<rootfs flavor>.yq` and `images/modifiers/platform/<platform name>/installer.yq`. Besides rootfs modifier may have a rootfs flavor in its name, e.g. `images/modifiers/platform/<platform name>/rootfs-lts.yq`. The flavor cannot be passed directly to the Makefile, but it can be used in the Makefile to generate a specific `rootfs-$(HV)-$(PLATFORM)-<rootfs flavor>.yml` file. If rootfs and installer shares the same modifiers, the `images/modifiers/platform/<platform name>/` directory may contain only a single file, e.g. `images/modifiers/platform/<platform name>/<platform name>.yq`.
  *If the platform doesn't require any specific modifiers, the `images/modifiers/platform/<platform name>/` directory may not exist at all.

All intermediate files generated in `images/out/` can be inspected to debug modifiers.

When you run `make rootfs.tar`, or any target that depends upon it, the following happens:

1. The Makefile includes [kernel-version.mk](../kernel-version.mk). This sets the variable `KERNEL_TAG` inside the make process to a specific docker image tag, based on the `ZARCH` and, if set, `PLATFORM`
1. The Makefile sees a dependency on `images/out/rootfs-$(HV)-$(PLATFORM)-[<rootfs flavor>].yml`
1. The Makefile runs `tools/compose-image-yml.sh -b images/rootfs.yml.in -v "$(ROOTFS_VERSION)-$(HV)-$(ZARCH)" -h $(HV) -o images/out/rootfs-$(HV)-$(PLATFORM)-[<rootfs flavor>].yml.in images/modifiers/hv/$(HV).yq images/modifiers/$(PLATFORM)/[rootfs-<flavor>| insstaller | <platform-name>].yq`, i.e. the utility [compose-image-yml.sh](../tools/compose-image-yml.sh), passing it:
   * the base template `images/rootfs.yml.in`, i.e. input file
   * the version string, which is the `ROOTFS_VERSION`, hypervisor, and architecture
   * the hypervisor
   * the output file, specifically `images/out/rootfs-$(HV)-$(PLATFORM)-[<rootfs flavor>].yml`
   * one or more modifiers: from `images/modifiers/hv/*` and/or `images/modifiers/$(PLATFORM)/*`
1. `compose-image-yml.sh` does the following:
   1. For each modifier, if any, apply it to the base template, and save the result to the provided output file.
   1. Search through the output file for the string `EVE_HV` and, if found, replace it with the hypervisor.
   1. If the version argument, which was generated from the git commit, contains the phrase `dirty`, i.e. uncommitted, then change the `PILLAR_TAG` in the output file to `PILLAR_DEV_TAG`, which will be used in a later stage.
1. The Makefile runs `./tools/parse-pkgs.sh images/out/rootfs-$(HV)-$(PLATFORM)-[<rootfs flavor>].yml.in > images/out/rootfs-$(HV)-$(PLATFORM)-[<rootfs flavor>].yml`, i.e. the utility [parse-pkgs.sh](../tools/parse-pkgs.sh), passing it as an input the HV-specific template generated in the previous step `rootfs-$(HV).yml.in`, and saving the output to the final `images/out/rootfs-$(HV)-$(PLATFORM)-[<rootfs flavor>].yml` file. In addition, the variable `KERNEL_TAG` is passed as an environment variable.
1. `parse-pkgs.sh` does the following:
    1. Gets the package tag for each directory in [pkg/](../pkg/) via `linuxkit pkg show-tag ${dir}`, and save it to variable which looks like `<PKGNAME>_TAG`, e.g. `PILLAR_TAG` or `WWAN_TAG`.
    1. Go through the input file - the HV-specific template - and replace the tags with the appropriate values. This includes the value of `KERNEL_TAG` as passed by the Makefile on calling `parse-pkgs.sh`.
1. The Makefile generates `rootfs.tar` via `./tools/makerootfs.sh tar -y images/out/rootfs-$(HV)-$(PLATFORM)-[<rootfs flavor>].yml -t path/to/rootfs.tar -a $(ZARCH)`, i.e. it runs [makerootfs.sh](../tools/makerootfs.sh), passing it the following arguments:
    1. The target format, i.e. `tar`
    1. `-a $(ZARCH)` - the architecture
    1. `-t $(PATH)` - path to the target output file
    1. `-y $(YML)` - path to the yml file, as generated in previous steps
1. `makerootfs.sh` runs `linuxkit build` to generate the final `rootfs.tar`

The above process creates several challenges, which will, eventually, be cleaned up:

1. It is necessary to pre-process the actual source files before generating an image. It is not possible to run `linuxkit build` manually to generate an image. This makes building and debugging individual steps harder.

These are all due to constraints within the usage of the `yml` files. If a cleaner solution requires upstreaming into linuxkit, it will be added to the [UPSTREAMING.md](./UPSTREAMING.md) file.

### Platform-specific

The current process uses the control knob `PLATFORM` in the following places in the Makefile:

* As a value in the included [kernel-version.mk](../kernel-version.mk), in order to set `KERNEL_TAG`, which is passed to [parse-pkgs.sh](../tools/parse-pkgs.sh).
* As the first argument to [prepare-platform.sh](../tools/prepare-platform.sh) in the Makefile targets for `live.*`, `installer.*` and `verification.*`, which, in turn, uses it to add specific files to the build and output directories prior to making the final image.
* In the final eve image `lf-edge/eve`, specifically the entrypoint [runme.sh](../pkg/eve/runme.sh), where the platform is passed as `-p` argument when calling `docker run`, and is used to modify the final layout.

### Note for developers

`make live` typically requires a significant amount of time, approximately 3 minutes, to generate a tarball and the resulting squashfs image. This delay can significantly slow down the development cycles of code compilation, live testing, and iteration. During development, we support rapid live image update, for use during development only. This optimization uses the following procedure:

1. Creating a live image with an EXT4 root filesystem. The live command also supports the EXT4 format for the root filesystem, resulting in a larger image size. However, this format allows for a mutable root filesystem, enabling it to be remounted with read-write (RW) options. This flexibility provides greater freedom during EVE runtime as well as during the live image creation, facilitating on-the-fly modifications to the image instead of requiring a complete rebuild from scratch. First you need to create a live image with EXT4 as the following:

    `make ROOTFS_FORMAT=ext4 live`

1. To streamline the generation of an up-to-date live image, especially during iterative development cycles, you can patch the EXT4 rootfs partition with generated rootfs tar. This approach minimizes the time required for generating the whole live image. Below is the command for updating the EXT4 live image generated by the previous command:

    `make LIVE_UPDATE=1 live`

   The command generates the rootfs tarball and update the live image using the `guestfish` tool (which must be installed on the system, check the main Makefile for details). Command also implies the `ROOTFS_FORMAT=ext4` option for obvious reasons: files can't be updated on the read-only file-system.

This approach reduces creation of the resulting live image from 3 minutes to 20 seconds (approximately).

### Generating any yml

Note that the process above can be used to generate any yml file, not just `rootfs-$(HV).yml`. As long as
a modifier file exists, you can call `make images/rootfs-foo.yml` and it will try to generate
`images/rootfs-foo.yml`, treating `foo` as the hypervisor. This may not successfully build a final
`rootfs.tar`, but you can generate any yml file you want and then later directly try running
`linuxkit build` upon it.

## Image Contents

As described above, the bootable images - live `live.img` and installer `installer.raw` - are partitioned disk images with the following layouts:

### Live Image Contents

|partition|purpose|source|
|---|---|---|
|EFI|boot via grub|`makeraw.sh`|
|imga|Root partition A|`rootfs.img` from linuxkit build|
|imgb|Root partition B|`rootfs.img` from linuxkit build|
|conf|Config data|`config.img` from `tools/makeconfig.sh`|
|persist|Persistent storage|empty|

### Installer Image Contents

|partition|purpose|
|---|---|
|EFI|boot via grub|`makeraw.sh`|
|imga|Root partition A|`rootfs_installer.img` from linuxkit build|
|conf_win|Config data|`config.img` from `tools/makeconfig.sh`|

The rest of this section describes the contents of the root filesystem, both `rootfs.img` for live and `rootfs_installer.img` for installer.

### LinuxKit Summary

LinuxKit - which is used to build both `rootfs.img` and `rootfs_installer.img` - composes an operating system image from OCI container images. Depending on configuration, these are used to:

* insert a kernel directly on the booting operating system
* place files directly on the booting operating system, including `init`, via "init packages"
* create one-time onboot services that run in containers via [runc](https://github.com/opencontainers/runc)
* create one-time onshutdown services that run in containers via [runc](https://github.com/opencontainers/runc)
* create long-running services that run in containers via [containerd](http://containerd.io)

### Standard Packages

EVE uses a number of standard linuxkit packages. These are enumerated below. Others may be added later.

#### Standard Live Packages

* `init` packages
  * `linuxkit/init` - for the `init` process
  * `linuxkit/runc` - for `runc`
  * `linuxkit/containerd` - for `containerd`
  * `linuxkit/getty` - for `getty` to log in on console
* `onboot` packages
  * `linuxkit/sysctl`
  * `linuxkit/modprobe` - customized for the appropriate modules
  * `linuxkit/mount` - customized to mount the config partition as `/var/config`
* `services` packages
  * `linuxkit/openntpd` - for ntp

#### Standard Installer Packages

* `init` packages
  * `linuxkit/init` - for the `init` process
  * `linuxkit/runc` - for `runc`
  * `linuxkit/getty` - for `getty` to log in on console

### Custom Packages

The remaining packages are custom images built for EVE. All of the packages - and some tools - are in the [pkg/](../pkg/) directory. We intend at some point to separate out tools, which are used at build-time, into the `tools/` directory, from packages, which are actual OCI images loaded into a runnable image, which will remain in `pkg/`.

The following custom packages are used:

#### Custom Live Packages

* kernel: EVE uses its own custom kernel (taken from [eve-kernel](https://github.com/lf-edge/eve-kernel) project), rather than one of the standard linuxkit ones. This is primarily due to kernel modules and drivers, especially on arm, as well as Xen requirements.
* `init` packages:
  * `lfedge/eve-grub` - CoreOS inspired GRUB required to enable CoreOS-style dual partition upgrades. See [UPSTREAMING.md](./UPSTREAMING.md#grub) for a more detailed discussion of what is unique in this grub.
  * `lfedge/eve-fw` - various firmware required for device drivers.
  * `lfedge/eve-xen` - a single Xen binary required to boot EVE.
  * `lfedge/eve-gpt-tools` - ChromiumOS inspired tools and sgdisk required to enable CoreOS-style dual partition upgrades. See [UPSTREAMING.md](./UPSTREAMING.md#grub) for a more detailed discussion of what is unique in these versions of the gpt tools.
  * `lfedge/eve-dom0-ztools` - catch-all containers for tools helpful in developing and debugging EVE.
* `onboot` packages:
  * `lfedge/eve-rngd` - custom `lfedge/eve-rngd` package, rather than the standard linuxkit one. This micro-fork accommodates the [following hack](https://github.com/lf-edge/eve/blob/master/pkg/rngd/cmd/rngd/rng_linux_arm64.go) which provides some semblance of seeding randomness on ARM. Without this HiKey board won't boot.
* `services` packages:
  * `lfedge/eve-wwan` - WWAN drivers and software. 5G/LTE/3G/2G. See [wwan/README.md](../pkg/wwan/README.md) for detailed documentation.
  * `lfedge/eve-wlan` - WLAN drivers and software. Currently a glorified wrapper around wpa_supplicant.
  * `lfedge/eve-guacd` - [Apache Guacamole service](http://guacamole.apache.org/) that provides console and VDI services to running VMs and containers.

#### Custom Installer Packages

* kernel: EVE uses its own custom kernel (taken from [eve-kernel](https://github.com/lf-edge/eve-kernel) project), rather than one of the standard linuxkit ones. This is primarily due to kernel modules and drivers, especially on arm, as well as Xen requirements.
* `init` packages:
  * `lfedge/eve-grub` - CoreOS inspired GRUB required to enable CoreOS-style dual partition upgrades.
  * `lfedge/eve-devices-trees` - device trees for all the ARM platforms that EVE supports.
  * `lfedge/eve-xen` - a single Xen binary required to boot EVE.
  * `lfedge/eve-dom0-ztools` - catch-all containers for tools helpful in developing and debugging EVE.
* `onboot` packages:
  * `lfedge/eve-rngd` - custom EVE rngd package, rather than the standard linuxkit one. This micro-fork accommodates the [following hack](https://github.com/lf-edge/eve/blob/master/pkg/rngd/cmd/rngd/rng_linux_arm64.go) which provides some semblance of seeding randomness on ARM. Without this HiKey board won't boot.
  * `lfedge/eve-mkimage-raw-efi` - custom EVE version of `mkimage-raw-efi` to create an ext4 image, used to make the correct filesystems on the target install disk.

#### pillar

The package `pillar` contains, unsurprisingly, the `pillar` services that are responsible for managing the various components and deployments of a running EVE system. Its source is [pkg/pillar](../pkg/pillar). We need to start breaking this monolith down at some point, but for now everything sits in the same container.

`pillar` itself vendors EVE golang api, i.e. the golang-compiled protobufs defined in [api/proto](https://github.com/lf-edge/eve-api/tree/main/proto). These can be updated and compiled using the instructions in its repository [lf-edge/eve-api](https://github.com/lf-edge/eve-api/).

`pillar` depends upon the latest versions of these being available at its compile time in its vendor directory at [pkg/pillar/vendor](../pkg/pillar/vendor). The target `make proto-vendor` will vendor them into [pkg/pillar/vendor](../pkg/pillar/vendor).

##### pillar build variants

The package pillar is built using the Makefile command: `make pkg/pillar [VAR1=value1 VAR2=value2 ...]`

Depending on the values of optional variables, the following pillar build variants are currently available:

* `make pkg/pillar`: Production version of pillar for the KVM or Xen hypervisor. There is no difference
  in the pillar build between KVM and Xen hypervisors, and the default `HV=kvm` can be used for both.
  The name of the built pillar container is `lfedge/eve-pillar:<tag>`.
* `make pkg/pillar DEV=y`: Development version of pillar for the KVM or Xen hypervisor. Debug symbols
  are preserved and seccomp is disabled in the pillar container.
  The name of the built pillar container is `lfedge/eve-pillar-dev:<tag>`.
* `make pkg/pillar HV=kubevirt`: Production version of pillar for the KubeVirt hypervisor (EVE using
  K3s + KubeVirt to deploy applications as VMs inside Kubernetes Pods). Contains additional
  microservices and Go package dependencies specific to Kubernetes.
  The name of the built pillar container is `lfedge/eve-pillar-kube:<tag>`.
* `make pkg/pillar HV=kubevirt DEV=y`: Development version of pillar for the KubeVirt hypervisor.
  Debug symbols are preserved and seccomp is disabled in the pillar container.
  The name of the built pillar container is `lfedge/eve-pillar-kube-dev:<tag>`.

Only `lfedge/eve-pillar` is currently published to Dockerhub as part of `lf-edge/eve` Github actions
for the master branch and EVE releases.

### Building packages

Packages are built within a docker container as defined by the `Dockerfile` within the package directory. The `Dockerfile` also specifies how the package will be built within the container. Some packages have a separate script to built them which is then invoked using the `RUN` clause within the `Dockerfile`. For some others like the `kernel` package, the entire build script is specified within the `Dockerfile`. Finally, the built docker images are published [here](https://hub.docker.com/u/lfedge). Please note that since our organization on DockerHub is managed by Linux Foundation, we have to request that they create a new package namespace for us every time we add a new package. For example, if you're adding `pkg/eve-foo` you will have to request a `New Repository` named `https://hub.docker.com/r/lfedge/eve-foo` via [LF JIRA](https://jira.linuxfoundation.org/plugins/servlet/desk/portal/2). Don't forget to ask for permissions setting to be copied from `https://hub.docker.com/r/lfedge/eve`.

Packages are meant to be the building blocks for [reproducible builds](https://reproducible-builds.org/). Currently, however, the builds are not strictly speaking reproducible, but rather guaranteed. EVE build system is not bootstrapping everything from the source up, instead it uses [Alpine Linux](https://pkgs.alpinelinux.org/packages) as the source of binary artifacts. All of the Alpine binary packages that are consumed by EVE are collected in the Docker image archive and published under `lfedge/eve-alpine` name. That way, EVE build system _pins_ all Alpine packages that it needs and can guarantee that they won't change until the archive is updated. All of the packages in the archive are listed under [mirrors](../pkg/alpine/mirrors) folder and the archive can be updated by updating that list. While currently re-building of the archive image is done by fetching required packages from the official Alpine mirrors, we can always add an additional step of bootstrapping all the same packages from source (which will give EVE true reproducible builds).

Since updating content of the `lfedge/eve-alpine` package is a bit of an unusual process -- it is described in details in the [ALPINE.md](./ALPINE.md) document.

Reliance on `lfedge/eve-alpine` archive enforces a particular structure on individual Dockerfile from EVE packages. For one, they always start with `FROM lfedge/eve-alpine:TAG` and they always produce the final output in the `FROM scratch` step (to avoid layer dependency on the large `lfedge/eve-alpine` package). In addition, `lfedge/eve-alpine` archive package defines a helper script `eve-alpine-deploy.sh` that provides and easy entry point for setting up of the build environment and the final, Alpine-based output of the build. This helper script is driven by looking up the following environment variable (which are very similar to [Requires](https://docs.fedoraproject.org/en-US/packaging-guidelines/#_dependency_types) and [BuildRequires](https://docs.fedoraproject.org/en-US/packaging-guidelines/#buildrequires) in RPMs):

* PKGS, PKGS_amd64, PKGS_arm64, PKGS_riscv64: used to list packages required for the final binary output of the build
* BUILD_PKGS, BUILD_PKGS_amd64, BUILD_PKGS_arm64, BUILD_PKGS_riscv64: used to list packages required to be present for the build itself, but not in the final output

The only tiny annoyance is that one should not forget an explicit `RUN eve-alpine-deploy.sh` stanza in the Dockerfile after these ENV variables are defined. Calling `eve-alpine-deploy.sh` in the RUN stanza has an effect of all the BUILD time packages getting installed in the build context and all the runtime packages getting installed in the special folder `/out` (if there are additional binary artifacts produced by the build -- they too need to be added to the `/out` folder).

A typical EVE Dockerfile drving the build will start from something like:

```shell
FROM lfedge/eve-alpine:XXX as build
ENV PKGS foo bar
ENV PKGS_arm64 baz-for-arm
ENV BUILD_PKGS gcc go
RUN eve-alpine-deploy.sh
...
FROM scratch
COPY --from=build /out/ /
```

One can build each package independently via:

```shell
make pkg/<name>
```

For example, to build `guacd`:

```shell
make pkg/guacd
```

To build all of the dependent packages:

```shell
make pkgs
```

In some cases, the `pkg/<name>` rule may rebuild more than intended, as they
specify required dependencies.  In this case, it may be more efficient to use
`make eve-<name>`, such as when testing changes in the `pillar` package:

```shell
make eve-pillar
```

All of these packages are published regularly to the dockerhub registry, so it is not strictly necessary to rebuild them, unless you are changing a package and want to publish, or are working with a local custom build.

**Note:** The net effect of this is that if you try to build `rootfs.img` or `installer.img` and reference a package that is _not_ published on the docker hub or available as a local image, it will _not_ try to build it locally for you; this functionality is not available in linuxkit. Instead, it will simply fail. You _must_ build the package and at least have it available in your local cache for the `rootfs.img` or `installer.img` build to succeed.

#### Building packages with runtime stats

Packages (currently Pillar) support collecting runtime memory and cpu statistics offered by Golang runtime. Collected statistics collected are sent over UDP to a [statsd](https://github.com/statsd/statsd) daemon running outside of EVE. To enable this, change the `RSTATS_ENDPOINT` (statsd endpoint) and `RSTATS_TAG` (the custom string used for tagging collected stats) inside `pkg/pillar/build-rstats.yml` to a proper value, then build:

```shell
make pkg/pillar RSTATS=y
```

To see the result, before running the image run statsd and graphite, for example:

```shell
docker pull graphiteapp/graphite-statsd
docker run -p 8080:80 -p 8125:8125/udp --rm --name statsd graphiteapp/graphite-statsd
```

While the EVE is running, navigate to `http://IP:8080/dashboard` and find the result under `stats.gauges`.

#### Reproducible Kernel build and versioning

Kernel packages ("pkg/kernel" and "pkg/new-kernel") are configured to produce a bit-by-bit reproducible kernel, to this end a `build.yml` is generated at build time to set the following variables to a static value:

```shell
KBUILD_BUILD_USER=eve
KBUILD_BUILD_HOST=eve
KCONFIG_NOTIMESTAMP=true
```

In addition, both `KBUILD_BUILD_TIMESTAMP` and `SOURCE_DATE_EPOCH` variables are set to the last commit date of the respective package, This configuration results in having a static version string (`/proc/version`) on every build. In case there is uncommitted changes in the kernel(s) directory, kernel gets build normally without any static time.

This process can be used to compare eve images that are build in a trusted environment vs CI, making sure the automated build process is intact and not malicious or compromised. For this purpose, you can use [rootfs-diff.sh](../tools/rootfs-diff.sh) to compare two builds. The script accepts the path of the mounted rootfs.img files (you need to mount a RW overlay on top; check the comments on the script), ideally you should see no output after the diff is finished:

```bash
$ rootfs-diff.sh /tmp/rfs-one/ tmp/rfs-two/
[1] Removing the signing key from kernel...
[1] Removing the signature form kernel modules...
[2] Removing the signing key from kernel...
[2] Removing the signature form kernel modules...
[*] Diffing the two rootfs...
$
```

But in case the two builds differ, the script outputs a list of files:

```bash
$ rootfs-diff.sh /tmp/rfs-one/ tmp/rfs-two/
[1] Removing the signing key from kernel...
[1] Removing the signature form kernel modules...
[2] Removing the signing key from kernel...
[2] Removing the signature form kernel modules...
[*] Diffing the two rootfs...
Files /tmp/rfs-one/boot/kernel and /tmp/rfs-two/boot/kernel differ
Files /tmp/rfs-one/lib/modules/5.10.121-default/kernel/net/can/can.ko and /tmp/rfs-two/lib/modules/5.10.121-default/kernel/net/can/can.ko differ
$
```

#### Buil-time kernel module signing

EVE kernel is configured to only load signed kernel modules, the module signing happens automatically during the build with a build-time generated throw-away key. But if you are willing to sign the modules using your own key, generate a key:

```shell
openssl req -new -nodes -utf8 -sha256 -days 36500 -batch -x509 \
   -config x509.genkey -outform PEM -out kernel_key.pem \
   -keyout kernel_key.pem
```

and place the `.pem` file in the `/eve/pkg/kernel/certs` directory. You can respectively change the `x509.genkey` template too.

## Summary of Build Process

This section provides an overview of the processes used to create the
following components:

* Live Images
* Installer Images

### Live Images

```text
+-------+                                +--------+
| pkg/* +-------+                     +--+ conf/  |
+-------+       |                     |  +--------+
+-------+       |                     |
| pkg/* +-------+                     |
+-------+       |linuxkit via         |
                |makerootfs.sh        |
                |                     |
+-------+       |                     |
| pkg/* +-------+                     |
+-------+       v                     v
       +--------+--------+   +--------+---------+
       |                 |   |                  |
       |   rootfs.img    |   |   config.img     |
       |                 |   |                  |
       +-+---------------+   +----------------+-+
         |                                    |
         |      live.raw                  |
         |     +---------------------------+  |
         |     |  efi                      |  |
         |     +---------------------------+  |
         +----->  imga                     |  |
         |     |                           |  |
         |     +---------------------------+  |
         +----->  imgb                     |  |
               |                           |  |
               +---------------------------+  |
               |  conf                     <--+
               |                           |
               +---------------------------+
               |  persist                  |
               |                           |
               +----------------+----------+
                                |
                live.qcow2  |
               +----------------v----------+
               |                           |
               |                           |
               +---------------------------+

```

### Installer Images

```text
+-------+                                +--------+
| pkg/* +-------+                     +--+ conf/  |
+-------+       |                     |  +--------+
+-------+       |                     |
| pkg/* +-------+                     |
+-------+       |linuxkit via         |
                |makerootfs.sh        |
                |                     |
+-------+       |                     |
| pkg/* +-------+                     |
+-------+       v                     v
       +--------+--------+   +--------+---------+
       |                 |   |                  |
       |   rootfs.img    |   |   config.img     |
       |                 |   |                  |
       +--------+--------+   +--------------+---+
                |                           |
+-------+       +------------------------+  |
| pkg/* +-----+ linuxkit via             |  |
+-------+     | makerootfs.sh            |  |
+-------+     |                          |  |
| pkg/* +-----+ rootfs_installer.img     |  |
+-------+    +v-----------------------+  |  |
             |                        |  |  |
             |                        |  |  |
             |                        |  |  |
             |                        |  |  |
             |                        |  |  |
             |                        |  |  |
             |                        |  |  |
             | /bits/rootfs.img <--------+  |
             | /bits/config.img <-----------+
             |                        |
             |                        |
             +------------------------+
                                |makeflash.sh
               installer.raw    |
             +------------------v-----+
             |                        |
             |                        |
             +------------------------+

```

## Build Tools

The following are build tools used to create EVE images, their purpose and source:

* [linuxkit](https://github.com/linuxkit/linuxkit) - build bootable operating system images by composing OCI images and raw files together. Used to create `rootfs.img` and `rootfs_installer.img`. Installed in `build-tools/bin/`
* [manifest-tool](https://github.com/estesp/manifest-tool) - create OCI v2 manifest images that can reference other images based on architecture or operating system. Enables a single image tag, e.g. `lfedge/foo:1.2` to be resolved automatically to the actual image that works on the current architecture and operating system at run-time. Installed in `build-tools/bin/`
* [makerootfs.sh](../makerootfs.sh) - call `linuxkit` to build a bootable image's filesystem, in tar format, for `rootfs.img` or `rootfs_installer.img`. Passes the resultant tar stream to a container from `pkg/mkrootfs-squash` or `pkg/mkrootfs-ext4`, depending on desired output format.
* [mkrootfs-squash](../pkg/mkrootfs-squash) or [mkrootfs-ext4](../pkg/mkrootfs-ext4) - take a build rootfs from the previous step as stdin in tar stream format, customize it with a filesystem UUID and other parameters, and create a squashfs or ext4 filesystem.
* [makeflash.sh](../makeflash.sh) - take an input tar stream of several images, primarily `rootfs.img` and `config.img`. Create a file to use as an image of a target size or default. Passes the resultant tar stream to a container from `pkg/mkimage-raw-efi`.
* [mkimage-raw-efi](../pkg/mkimage-raw-efi) - create an output file that represents an entire disk, with multiple partitions. By default, `efi`,`imga`,`imgb`,`config`,`persist`. The installer image creates only `efi`,`img`,`config`.
* [tools/makeconfig.sh](../tools/makeconfig.sh) - package up the provided directory, normally [conf/](../conf/) into a tar stream, and pass to a container from `pkg/mkconf`.
* [mkconf](../pkg/mkconf) - combine the input tar stream with defaults in `/conf/` from `lfedge/eve-pillar` into a new container image in `/`. Create a FAT32 disk image from it.
* [parse-pkgs.sh](../parse-pkgs.sh) - determine the correct latest hash to use for all packages and higher-order components. See [parse-pks](#parse-pkgs).

### parse-pkgs

In many cases, we want to build an image not from a specific commit we actively know for individual packages, but from the latest specific version currently available. For example, if our linuxkit config `yml` looks as follows:

```yml
kernel:
  image: lfedge/eve-kernel:7cfa13614bb99a84030db209b6c9a0696c7d3315-amd64
  cmdline: "rootdelay=3"
init:
  - lfedge/eve-grub:97e7b1404e7c9d141eddb58294fcff019f61571b-amd64
  - lfedge/eve-device-trees:18377dd0bc3c33a1602e94a4c43aa0b3c51badb9-amd64
  - lfedge/eve-fw:1d8c22ae31c42d767ba648b186db4ea967a9c569-amd64
  - lfedge/eve-xen:f51bf3d17fad15b71242befbddec96e177132a99-amd64
  - lfedge/eve-gpt-tools:fe878611e4e032ea10946cbc9a1c3d5b22349dc4-amd64
  - lfedge/eve-dom0-ztools:b53cd1b5785c128371a5997e3a6e16007718c12d-amd64
```

We may want to rebuild using the latest version currently available to us of each of the above packages. If we changed 1, 3 or even all of them, it is a tedious and error-prone job to change the hashes of the commits for each of them.

Similarly, a `pkg/` may be sourced from another package which, in turn, has a specific commit. For example, the first line of the generated qrexec-dom0 [Dockerfile](../pkg/qrexec-dom0/Dockerfile) is:

```yml
FROM lfedge/eve-xen-tools@sha256:4a6d0bcfc33a3096398b4daa0931f9583c674358eeb47241e0df5f96e24c0110 as xentools
```

The Dockerfile mentioned above is not checked into the repository, but instead generated from a template by a parse-pkgs script.

The purpose of [parse-pkgs](../parse-pkgs.sh) is to collect the actual hashes of the latest version of every relevant package and either report them to stdout or modify a template file à la sed.

It does the following:

1. Receive the `DOCKER_ARCH_TAG` var and, if not present, determine it from `uname -m` and canonicalize it.
2. Receive the `EVE_VERSION` var and, if not present, determine it from `eve_version`.
3. Determine the latest tag for each package in a list, roughly approximating every directory in `pkg/` using `linuxkit pkg show-tag pkg/<dir>` and save it as a var with name `<pkg-as-uppercase>_TAG`, e.g. `STRONGSWAN_TAG`
4. For internal packages that combine other packages - `lfedge/eve-zedctr` and `lfedge/eve` - do a more complicated versioning:
    1. `cat pkg/<pkg>/Dockerfile.in`
    2. resolve all of the tags to actual latest versions to create a ready-to-run `Dockerfile`
    3. create a hash of the generated `Dockerfile`
5. Modify all stdin to replace any tags with the appropriate named and hashed packages, e.g. `STRONGSWAN_TAG` to `lfedge/eve-strongswan@sha256:abcdef5678`

The current build process with `parse-pkgs.sh` creates some challenges:

* The templated inputs, e.g. `Dockerfile.in` or `rootfs.yml.in`, are easily checked into version control, while the generated `Dockerfile` or `rootfs.yml` are not. These leave artifacts throughout the tree that are the sources of actual builds and should be checked in.
* The generated files tend to be architecture-specific. These can be resolved by using multi-arch manifests. This, in turn, will make the previous issue easier to solve.
* `parse-pkgs.sh` is run with every invocation of `make`, even `make -n`. The lists of local packages to be resolved with `linuxkit pkg show-tag` is fairly quick, pulling down and resolving the actual images for external packages is slow. In all cases, if possible, these should be deferred until actual build requires them. This is resolvable via `Makefile` changes.
* The list of packages is hard-coded into `parse-pkgs.sh`. This makes it brittle and hard to add packages. If possible, this should be moved to parsing the `pkg/` directory.

Last but not least, is this completely necessary?

* `images/*.yml`: The need to update `images/*.yml` is understood, as these packages change a lot. Even so, the utilities might be better structured as a separate external utility that is run manually. Most of the time, you just build from a static `rootfs.yml` or `installer.yml`. When you want to update them, you run `update-images` (or similar) and it updates them. Finally, you commit when a good build is ready.
* `pkg/*/Dockerfile`: The need to generate `Dockerfile` for many of the packages may mean too much cross-dependency, which can be brittle. It is possible that this is necessary, and there is no other way around it. However, we should explore how we can simplify dependencies.

## Cross-compilation support

### cross-compilers package

In order to enable cross-compilation we add `pkg/cross-compilers` which contains `binutils`, `gcc` and `g++` prepared with target architecture different from host one.

Cross-compilers support matrix are inside the following table (`Y` - supported, `N` - not supported, `-` - not expected).

| target arch | x86_64 host | aarch64 host | riscv64 host |
|-------------|:-----------:|:------------:|:------------:|
|    x86_64   |      -      |      Y       |      N       |
|   aarch64   |      Y      |      -       |      N       |
|   riscv64   |      Y      |      Y       |      -       |

The package use [aports](https://gitlab.alpinelinux.org/alpine/aports) repository as a base to build cross-compilers
with the same revision as used for eve-alpine package. It helps us to use the same versions of tools with the same configuration and patches applied.
Only two patches applied to aports repository:

1. [0001-only-cross-compile-prepare.patch](.../pkg/cross-compilers/patches/aports/0001-only-cross-compile-prepare.patch) - allow us to use the bootstrap script provided in repo and stops the process of bootstrap right after preparing of cross-compilers
2. [0002-adjust-sysroot.patch](.../pkg/cross-compilers/patches/aports/0002-adjust-sysroot.patch) - modifies sysroot configured during building of gcc to be pointed onto reasonable directory (e.g. `/usr/riscv64-alpine-linux-musl` instead of `/home/builder/sysroot-riscv64` bootstrap process use internally)

Note that cross-compiler packages inside aports are not distributed and involved in the bootstrap process only, so patches are not expected to be upstreamed.

The build process of the image is quite time-consuming, but we need to rebuild it only in case of moving onto the next alpine release, e.g. from `3.16` to `3.17`, when we will update gcc/binutils.
Update of packages inside `eve-alpine` without moving to the next Alpine release will not affect versions of gcc as we reuse them from cache.

Building of cross-compilers for `riscv64` host architecture is not supported now because of no `gcc-gnat` available (additional patches required).

### Enabling of cross-compilation

Cross-compilation support depends on compilers we use and ways of configuring compilers. The implementation of the process is quite varied and may not be possible. We should support both cases: native and cross-compilation for all targets.
The main reason of enabling cross-compilation is to speedup build for another target architecture and acceleration can reach orders of magnitude.
It is not reasonable to enable cross-compilation in all packages as it complicate the logic, only for ones which consume significant time.

In order to cross compile, you need the following at compile time:

* env vars, specifically:
  * `BUILDARCH` - the architecture in go format for where you are building, e.g. amd64 or arm64
  * `EVE_BUILD_ARCH` - the architecture in uname format for where you are building, e.g. x86_64 or aarch64
  * `TARGETARCH` - the architecture in go format for the platform you are targeting, e.g. amd64 or arm64
  * `EVE_TARGET_ARCH` - the architecture in uname format for the platform you are targeting, e.g. x86_64 or aarch64
  * `CROSS_COMPILE_ENV` - cross-compiler prefix to use in `CC` with gcc suffix or in `CROSS_COMPILE` env variable
* compilers in your build architecture that can compile binaries for your target architecture
  * `gcc`/`g++`/`binutils` with cross-compilation support - provided by `lfedge/eve-cross-compilers`
  * libraries for the target architecture - natively from `eve-alpine` for the target architecture

Below we provide step-by-step processes for cross-compilation in Dockerfile, each step of which provides one or more of the requirements:

1. Add another base eve-alpine image with `--platform=${BUILDPLATFORM}`. This way we enforce builder to use the same platform we are running on (not the target platform):

    ```dockerfile
    ARG BUILD_PKGS_BASE="git gcc linux-headers libc-dev make linux-pam-dev m4 findutils go util-linux make patch \
                         libintl libuuid libtirpc libblkid libcrypto1.1 zlib tar"
    # native base image
    FROM lfedge/eve-alpine:e0280f097450d1f53dd483ab98acd7c7cf2273ce as build-native
    ARG BUILD_PKGS_BASE
    RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh
    # cross-compile base image
    FROM --platform=${BUILDPLATFORM} lfedge/eve-alpine:e0280f097450d1f53dd483ab98acd7c7cf2273ce as build-cross
    ARG BUILD_PKGS_BASE
    RUN BUILD_PKGS="${BUILD_PKGS_BASE}" eve-alpine-deploy.sh
    ```

2. Use cross-compilers image for the host platform to install packages from it later:

    ```dockerfile
    FROM --platform=${BUILDPLATFORM} lfedge/eve-cross-compilers:e39535ae301b2b64e900e434ef197612cb3a6fa9 AS cross-compilers
    ```

3. Add libraries required to build for the target platform:

    ```dockerfile
    FROM lfedge/eve-alpine:e0280f097450d1f53dd483ab98acd7c7cf2273ce AS cross-compile-libs
    ENV PKGS musl-dev libgcc libintl libuuid libtirpc libblkid
    RUN eve-alpine-deploy.sh
    ```

4. Adjust `EVE_TARGET_ARCH` environment variable for cross-compiler:

    ```dockerfile
    FROM build-cross AS build-cross-target-arm64
    ENV EVE_TARGET_ARCH=aarch64
    FROM build-cross AS build-cross-target-amd64
    ENV EVE_TARGET_ARCH=x86_64
    ```

5. Install cross-compilers and copy libraries into your image:

    ```dockerfile
    FROM build-cross-target-${TARGETARCH} AS build-cross-target
    ENV CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-
    COPY --from=cross-compilers /packages /packages
    RUN apk add --no-cache --allow-untrusted -X /packages build-base-"${EVE_TARGET_ARCH}"
    COPY --from=cross-compile-libs /out/ /usr/"${EVE_TARGET_ARCH}"-alpine-linux-musl/
    ```

6. Chain images to use the same notation for cross and native cases:

    ```dockerfile
    # cross-compilers
    FROM build-cross-target AS target-arm64-build-amd64
    FROM build-cross-target AS target-amd64-build-arm64
    # native
    FROM build-native AS target-amd64-build-amd64
    FROM build-native AS target-arm64-build-arm64
    ```

7. Use cross compilation (here we put go sample that uses cgo):

    ```dockerfile
    FROM target-${TARGETARCH}-build-${BUILDARCH} AS build
    ARG TARGETARCH
    ENV GOFLAGS=-mod=vendor
    ENV GO111MODULE=on
    ENV CGO_ENABLED=1
    ENV GOOS=linux
    # define target arch
    ENV GOARCH=${TARGETARCH}
    # define cross-compiler to use
    ENV CC=${CROSS_COMPILE_ENV}gcc
    # ADD / /
    # RUN go build .
    ```

8. Copy out build artifacts into the image based on target arch. Do not forget to install runtime libraries there.

Note that `EVE_BUILD_ARCH` and `EVE_TARGET_ARCH` environment variables are set in eve-alpine image to be aligned with its arch (e.g. `x86_64` for `adm64`), so we need to override them only for cross-compilation.
`BUILDARCH` and `TARGETARCH` exposed by build system itself.

The whole flow looks like this:

* For native builds, e.g. amd64 -> amd64, stage `build` inherits from `target-amd64-build-amd64`, which inherits from `build-native`, which is just `eve-alpine`.
* For cross-compile builds, e.g. amd64 (host) -> arm64 (target):
  * Stage `build` inherits from `target-arm64-build-amd64`, which inherits from `build-cross-target`
  * Stage `build-cross-target`:
    * installs the cross-compilers for host (amd64) and target (arm64) arch combination from `cross-compilers` image. We use `EVE_TARGET_ARCH` there to compose the package name notation `build-base-aarch64` to install.
    * installs the target arch libraries from `cross-compile-libs`, which is based on `eve-alpine` for the `TARGETARCH`
    * sets `CROSS_COMPILE_ENV="${EVE_TARGET_ARCH}"-alpine-linux-musl-` environment variable to use later as cross-compile prefix
    * inherits from `build-cross-target-${TARGETARCH}`, which adjust the `EVE_TARGET_ARCH` environment variable and inherits from `build-cross` stage based on `eve-alpine`

## Using a local container registry

All containers built by the EVE project are available in the official [LF-Edge's Docker HUB](https://hub.docker.com/u/lfedge).
However, developers might want to pull and/or push all containers to a local container registry for debugging and development purposes.
EVE's build system allows to override the default docker registry through the `REGISTRY` variable. For example:

1. Start docker registry at local port 5001 (to not clash with a running docker registry)

    ```sh
    docker run -d -p 5001:5000 --name lcreg registry:2
    ```

1. Build EVE with the local registry URL

    ```sh
    make REGISTRY="localhost:5001" pkgs eve
    ```

1. Push packages to the local registry

    ```sh
    make REGISTRY="localhost:5001" LINUXKIT_PKG_TARGET=push pkgs eve
    ```

1. A list of packages pushed to the local registry can be retrieved with the following command:

    ```sh
    curl -s http://localhost:5001/v2/_catalog? | jq
    ```

    Output will be in JSON format, for instance:

    ```json
    {
      "repositories": [
        "lfedge/eve",
        "lfedge/eve-acrn",
        "lfedge/eve-acrn-kernel",
        "lfedge/eve-alpine",
        "lfedge/eve-apparmor",
        "lfedge/eve-bpftrace",
        "lfedge/eve-bsp-imx",
        "lfedge/eve-cross-compilers",
        "lfedge/eve-gpt-tools",
        "lfedge/eve-grub",
        "lfedge/eve-ipxe",
        "lfedge/eve-kvm-tools",
        "lfedge/eve-measure-config",
        "lfedge/eve-memory-monitor",
        "lfedge/eve-mkconf",
        "lfedge/eve-mkimage-raw-efi",
        "lfedge/eve-newlog",
        "lfedge/eve-optee-os",
        "lfedge/eve-recovertpm",
        "lfedge/eve-rngd",
        "lfedge/eve-storage-init",
        "lfedge/eve-u-boot",
        "lfedge/eve-udev",
        "lfedge/eve-uefi",
        "lfedge/eve-watchdog",
        "lfedge/eve-xen"
      ]
    }
    ```
