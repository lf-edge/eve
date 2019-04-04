# Building EVE

This document describes how the EVE build process works, its dependencies, inputs and outputs. The planned complementary document [CONTRIBUTING.md](./CONTRIBUTING.md) describes how to contribute to EVE.

## Dependencies

EVE uses several build tools, some of which are prerequisites, while others are installed as needed.

### Prerequisities

You must have the following installed in order to build EVE:

* [Go](https://golang.org) Eventually, this requirement will be replaced by running in docker.
* [docker](https://www.docker.com/get-started) 
* [qemu](https://www.qemu.org) (optional) Required only if you wish to run the generated image. On macOS, easiest to install via [homebrew](https://brew.sh) via `brew install qemu`.
* [git](https://git-scm.com) which you must have to clone this repository.

### Installed As Needed

* [manifest-tool](https://github.com/estesp/manifest-tool) - CLI used to create multi-architecture manifests of docker images.
* [linuxkit](https://github.com/linuxkit/linuxkit) - CLI used to build actual EVE bootable images.
* [dep](https://github.com/golang/dep) - CLI used to install dependencies for other "Installed as Needed" requirements

Each "Installed as Needed" build tool will place its final executable in `build-tools/bin/`, e.g. `build-tools/bin/linuxkit` or `build-tools/bin/manifest-tool`. Each tool, in turn, has a directory in `build-tools/src/`, e.g. `build-tools/src/linuxkit/`. The `src/` directory does _not_ contain all of the code for the tool. Instead, it has the following:

* `Gopkg.toml` - with all of the dependencies including the specific version of the package itself as a `constraint`
* `Gopkg.lock` - generated from a run
* `dummy.go` - an empty file to give go something to build

To build a specific tool, you can execute `make bin/<tool-name>`, e.g. `make bin/manifest-tool`, in `build-tools`, e.g.:

```
make -C build-tools bin/manifest-tool
```

This target does the following:

1. Set `GOPATH=$PWD`, i.e. the `build-tools/` directory
2. If `dep` isn't available, `go get` it
3. `cd src/<tool> && dep ensure -v`. This step installs the tool's go source in `vendor/`, as it is in `Gopkg.toml`
4. `cd src/<tool>/vendor/<path>` ; this path will change based on the tool.
5. `go build <options> -o $GOPATH/bin/<tool>`

To build all of the tools, run `make -C build-tools all`, or in the project root directory, just `make build-tools`

#### Reasoning

The normal process for installing go-based binaries is to execute `go get` with options, e.g.

```
go get -u github.com/linuxkit/linuxkit/src/cmd/linuxkit
go get -u github.com/estesp/manifest-tool
```

EVE uses a somewhat non-standard build process for these tools to ensure specific versions without polluting the user's normal workspace. 

## Output Components

The following are the output components from the build process and their purpose. There are two kinds of components: final, intended for actual direct usage, and interim, used to build the final components. Some interim components may be removed as part of the build finalization process.

#### Final

* `fallback.img` - a symlink to `fallback.qcow2`
* `fallback.qcow2` - the final bootable live disk image in [qcow2](https://en.wikipedia.org/wiki/Qcow) format
* `installer.raw` - a bootable image that can install EVE on a local device. The installer is intended to be flashed to a USB or SD device, or booted via PXE, and then run to install on a local drive.
* `installer.iso` - a bootable ISO image with a hidden EFI boot partition and an installer partition, with the contents of `installer.raw`. The installer is intended to be booted in a manner typical of iso files, and then run to install on a local drive.

#### Interim

* `rootfs.img` - a live bootable rootfs filesystem image. This can be either [squashfs](https://en.wikipedia.org/wiki/SquashFS) (default) or [ext4](https://en.wikipedia.org/wiki/Ext4). 
* `rootfs_installer.img` - a bootable rootfs filesystem image to run as an installer.
* `fallback.raw` - a live bootable disk image, will be converted to [qcow2](https://en.wikipedia.org/wiki/Qcow). Has 2 gpt partitions:
    1. UEFI partition with grub
    2. root partition from the above `rootfs.img`
* `config.img` - 1MB FAT32 image file containing basic configuration information, including wpa supplicant, name of the controller, onboarding key/cert pair, and other configuration information. 

## Build Process

The general rules for the build process are as follows.

All bootable images are built via [linuxkit](https://github.com/linuxkit/linuxkit), using standard linuxkit yml configuration files. Read documents at the [linuxkit repository](https://github.com/linuxkit/linuxkit) to learn more about how linuxkit works, composing OCI images to create a bootable disk. 

EVE builds one of two bootable images using linuxkit, depending on if you are building an installer or a live image, and then modifies them with various tools.

### Live

For a live bootable image, named `fallback.img`, we create the following dependencies in order:

1. `rootfs.img`
2. `config.img`
3. `fallback.raw`
4. `fallback.qcow2`


#### rootfs.img

`rootfs.img` is a bootable root filesystem. To build it:

1. Verify the existence of the linuxkit builder configuration file `images/rootfs.yml`. See notes on [generating yml](#generating-yml).
2. Call `makerootfs.sh images/rootfs.yml <format> rootfs.img`, which will:
    1. Build an image using `linuxkit` with a tar output format using `images/rootfs.yml` as the configuration file..
    2. Pipe the contents of the tar image to a docker container from either `mkrootfs-ext4` or `mkrootfs-squash`, depending on desired output format.
    3. `mkrootfs-*` takes the contents of the tar image, modifies `grub.cf`, builds it into an ext4 filesystem image, and streams it to stdout.
    4. Direct the output to the targeted filename, in this case `rootfs.img`.

We now have `rootfs.img`. 

#### config.img

`config.img` is a simple image containing the basic configurations necessary to run EVE. These files are intended to be on their own partition on the final image.

To build `config.img`:

1. Verify the existence of dependencies, essentially everything in `conf/`
2. Call the script to create the image: `./maketestconfig.sh conf config.img`. This will:
    1. tar up the contents of the config directory into a tar format.
    2. stream the contents of the tar format into a docker container from the image generated by `pkg/mkconf`. `mkconf` is an image that contains the `make-config` script and all of `/opt/zededa/examples/config` from [ztools](https://github.com/zededa/go-provision).
    3. `mkconf` creates a FAT32 image whose root is everything copied from ztools overwritten by everything from `$PWD/conf/`.
    4. `mkconf` saves the image to `config.img`

#### fallback.raw

`fallback.raw` is a live bootable raw disk image with both a rootfs and a UEFI boot partition.

To build `fallback.raw`:

1. Ensure `rootfs.img` and `config.img` are ready.
2. tar these two dependencies together and stream to [makeflash.sh](../makeflash.sh)
3. Call `./makeflash.sh -C <disksize> fallback.raw`, where _disksize_ is normally 8192MB
4. `makeflash.sh` creates an empty image of the target size at the target path, and then passes control to a docker container from the image generated by `pkg/mkimage-raw-efi`. It does _not_ pass on the names of the partitions to be created, depending on the default.
5. `mkimage-raw-efi`:
    1. extracts the contents of the tar stream to `/parts/`
    2. creates a partition for each of `efi`, `imga`, `imgb`, `conf`, `persist`
    3. Populates each partition with its appropriate contents:
        * `efi`: contents of `/EFI/BOOT/` from `/parts/rootfs.img`
        * `imga`/`imgb`: contents of `/parts/rootfs.img`
        * `conf`: contents of `/parts/config.img`
        * `persist`: contents of `/parts/persist.img` if it exists, else empty
    4. Populates the embedded boot partition with the grub `*.EFI` binary and `grub.cfg` file
    5. Validates the image.

#### fallback.qcow2

`fallback.qcow2` is the final version of the live bootable image, in qcow2 format.

To build `fallback.qcow2`:

1. Ensure that `fallback.raw` exists.
2. Convert it to `fallback.qcow2` via `qemu-img convert`
3. Remove `fallback.raw`

#### fallback.img

`fallback.img` is a convenience universal pointer to the final image.

To build `fallback.img`:

```
ln -s fallback.qcow2 fallback.img
``` 

### Installable

For an installable image, named `installer.img`, we create the following dependencies in order:

1. `rootfs.img`
2. `config.img`
3. `rootfs_installer.img`
4. `installer.raw`

#### rootfs.img

`rootfs.img` is built identically to how it is for a live bootable image, see [rootfs.img](#rootfs.img)

#### config.img

`config.img` is built identically to how it is for a live bootable image, see [config.img](#config.img)

#### rootfs_installer.img

`rootfs_installer.img` is the actual bootable image that installs EVE onto another storage medium, normally an on-board disk/ssd on a device.

To build `rootfs_installer.img`:

1. Ensure the existence of the prerequisites: `rootfs.img`, `config.img`, `images/installer.yml`. The `yml` file is the configuration file for using linuxkit to build the `rootfs_installer.img`. See notes on [generating yml](#generating-yml).
2. Call `makerootfs.sh images/installer.yml <format> rootfs_installer.img`, which will:
    1. Build an image using `linuxkit` with a tar output format using `images/installer.yml` as the configuration file..
    2. Pipe the contents of the tar image to a docker container from either `mkrootfs-ext4` or `mkrootfs-squash`, depending on desired output format.
    3. `mkrootfs-*` takes the contents of the tar image, modifies `grub.cf`, builds it into an ext4 filesystem image, and streams it to stdout.
    4. Direct the output to the targeted filename, in this case `rootfs_installer.img`.

#### installer.raw

`installer.raw` is a bootable raw disk installer image with both a rootfs and a UEFI boot partition.

To build `installer.raw`:

1. Ensure `rootfs_installer.img` and `config.img` are ready.
2. tar these two dependencies together and stream to [makeflash.sh](../makeflash.sh)
3. Call `./makeflash.sh -C <disksize> fallback.raw "efi imga conf_win"`, where _disksize_ is normally 350MB
4. `makeflash.sh` creates an empty image of the target size at the target path, and then passes control to a docker container from the image generated by `pkg/mkimage-raw-efi`. It _does_ pass on the names of the partitions to be created, limiting it to `efi`, `imga`, `conf_win`. There is no need for `imgb` or `persist` partitions for an installer image that will not be persisting data, and will not be updating its root filesystem.
5. `mkimage-raw-efi`:
    1. extracts the contents of the tar stream to `/parts/`
    2. creates a partition for each of `efi`, `imga`, `conf_win`
    3. Populates each partition with its appropriate contents:
        * `efi`: contents of `/EFI/BOOT/` from `/parts/rootfs.img`
        * `imga`: contents of `/parts/rootfs.img`
        * `conf_win`: contents of `/parts/config.img`. `conf_win` is different from `conf` only in the partition type. It is unclear why this matters for the installer.
        * `persist`: contents of `/parts/persist.img` if it exists, else empty
    4. Populates the embedded boot partition with the grub `*.EFI` binary and `grub.cfg` file
    5. Validates the image.

## Generating yml

As described earlier, the `yml` files used to generate the images via `linuxkit build` are in the [images/](../images/) directory. The actual files, e.g. `rootfs.yml` and `installer.yml`, are not checked in directly to source code control. Rather, these are _generated_ from `<ymlname>.yml.in`, e.g. [rootfs.yml.in](../images/rootfs.yml.in) and [installer.yml.in](../images/installer.yml.in). The generation is as follows:

```
parse-pkgs.sh <yml>.in > <yml>
```

This is used to replace the tags of various components in the `.yml.in` file with the correct current image name and tag for various packages, including the correct architecture. 

The output `.yml` file is stored in the same directory as the `.yml.in` file, i.e. [images/](../images/).

This creates several challenges, which will, eventually, be cleaned up:

1. The `images/` source directory is unclean, with both committed and non-committed code in the same directory.
2. The same input file, e.g. `rootfs.yml`, appears to be usable with different architectures, but actually is not, as it is architecture-specific.
3. It is necessary to pre-process the actual source files before generating an image. It is not possible to run `linuxkit build` manually to generate an image. This makes building and debugging individual steps harder.

These are all due to constraints within the usage of the `yml` files. If a cleaner solution requires upstreaming into linuxkit, it will be added to the [UPSTREAMING.md](./UPSTREAMING.md) file.

## Image Contents

As described above, the bootable images - live `fallback.img` and installer `installer.raw` - are partitioned disk images with the following layouts:

Live:

|partition|purpose|source|
|---|---|---|
|EFI|boot via grub|`makeraw.sh`|
|imga|Root partition A|`rootfs.img` from linuxkit build|
|imgb|Root partition B|`rootfs.img` from linuxkit build|
|conf|Config data|`config.img` from `maketestconfig.sh`|
|persist|Persistent storage|empty|

Installer:

|partition|purpose|
|---|---|
|EFI|boot via grub|`makeraw.sh`|
|imga|Root partition A|`rootfs_installer.img` from linuxkit build|
|conf_win|Config data|`config.img` from `maketestconfig.sh`|

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

**Live**

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

**Installer**

* `init` packages
    * `linuxkit/init` - for the `init` process
    * `linuxkit/runc` - for `runc`
    * `linuxkit/getty` - for `getty` to log in on console

### Custom Packages

The remaining packages are custom images built for EVE. All of the packages - and some tools - are in the [pkg/](../pkg/) directory. We intend at some point to separate out tools, which are used at build-time, into the `tools/` directory, from packages, which are actual OCI images loaded into a runnable image, which will remain in `pkg/`.

The following custom packages are used:

**Live**

* kernel: EVE uses its own custom kernel package, rather than one of the standard linuxkit ones. This is primarily due to kernel modules and drivers, especially on arm, as well as Xen requirements.
* `init` packages:
    * `zededa/grub` - 
    * `zededa/devices-trees` - 
    * `zededa/fw` - 
    * `zededa/xen` - 
    * `zededa/gpt-tools` - 
    * `zededa/dom0-ztools` - 
* `onboot` packages:
    * `zededa/rngd` - custom `zededa/rngd` package, rather than the standard linuxkit one. _Why?_
* `services` packages:
    * `zededa/wwan` - WWAN drivers and software. LTE? 3G? 2G?
    * `zededa/wlan` - WLAN drivers and software.
    * `zededa/guacd` - 
    * `zededa/zedctr` - a "catch-all" package for EVE tools; see below.

**Installer**

* kernel: EVE uses its own custom kernel package, rather than one of the standard linuxkit ones. _Why?_
* `init` packages:
    * `zededa/grub` - 
    * `zededa/devices-trees` - 
    * `zededa/xen` - 
    * `zededa/dom0-ztools` - 
* `onboot` packages:
    * `zededa/rngd` - custom EVE rngd package, rather than the standard linuxkit one. _Why?_
    * `zededa/mkimage-raw-efi` - custom EVE version of `mkimage-raw-efi` to create an ext4 image, used to make the correct filesystems on the target install disk.

#### zedctr

The package `zededa/zedctr` is a "catch-all" package, composed of many different packages that would go into `services` separately. Its source is [pkg/zedctr](../pkg/zedctr), and is comprised of many different services.

#### ztools

The package `ztools` contains the `go-provision` services that are responsible for managing the various components and deployments of a running EVE system. Its source is [go-provision](https://github.com/zededa/go-provision). 

### Building packages

Each package can be built independently via:

```
linuxkit pkg build <directory>
```

For example, to build `guacd`:

```
linuxkit pkg build pkg/guacd
```

Or from within the `pkg/guacd` directory:

```
linuxkit pkg build .
```

To simplify and collate building, you can run `make build` in the `pkg/` directory, or just `make -C pkg/ build`. This will build all of the dependent packages.

All of these packages are published regularly to the dockerhub registry, so it is not strictly necessary to rebuild them, unless you are changing a package and want to publish, or are working with a local custom build.

**Note:** The net effect of this is that if you try to build `rootfs.img` or `installer.img` and reference a package that is _not_ published on the docker hub or available as a local image, it will _not_ try to build it locally for you; this functionality is not available in linuxkit. Instead, it will simply fail. You _must_ build the package and at least have it available in your local cache for the `rootfs.img` or `installer.img` build to succeed.

## Summary of Build Process

### Live

```
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
         |      fallback.raw                  |
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
                fallback.qcow2  |
               +----------------v----------+
               |                           |
               |                           |
               +---------------------------+

```

### Installer

```

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
* [manifest-tool](https://github.com/estesp/manifest-tool) - create OCI v2 manifest images that can reference other images based on architecture or operating system. Enables a single image tag, e.g. `zededa/foo:1.2` to be resolved automatically to the actual image that works on the current architecture and operating system at run-time. Installed in `build-tools/bin/`
* [makerootfs.sh](../makerootfs.sh) - call `linuxkit` to build a bootable image's filesystem, in tar format, for `rootfs.img` or `rootfs_installer.img`. Passes the resultant tar stream to a container from `pkg/mkrootfs-squash` or `pkg/mkrootfs-ext4`, depending on desired output format.
* [mkrootfs-squash](../pkg/mkrootfs-squash) or [mkrootfs-ext4](../pkg/mkrootfs-ext4) - take a build rootfs from the previous step as stdin in tar stream format, customize it with a filesystem UUID and other parameters, and create a squashfs or ext4 filesystem.
* [makeflash.sh](../makeflash.sh) - take an input tar stream of several images, primarily `rootfs.img` and `config.img`. Create a file to use as an image of a target size or default. Passes the resultant tar stream to a container from `pkg/mkimage-raw-efi`.
* [mkimage-raw-efi](../pkg/mkimage-raw-efi] - create an output file that represents an entire disk, with multiple partitions. By default, `efi`,`imga`,`imgb`,`config`,`persist`. The installer image creates only `efi`,`img`,`config`.
* [maketestconfig.sh](../maketestconfig.sh) - package up the provided directory, normally [conf/](../conf/) into a tar stream, and pass to a container from `pkg/mkconf`.
* [mkconf](../pkg/mkconf) - combine the input tar stream with defaults in `/conf/` from `zededa/ztools` into a new container image in `/`. Create a FAT32 disk image from it.

