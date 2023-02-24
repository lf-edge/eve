# EVE is Edge Virtualization Engine

[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/4746/badge)](https://bestpractices.coreinfrastructure.org/projects/4746)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/lf-edge/eve/badge)](https://api.securityscorecards.dev/projects/github.com/lf-edge/eve)
[![Publish](https://github.com/lf-edge/eve/actions/workflows/publish.yml/badge.svg?branch=master)](https://github.com/lf-edge/eve/actions/workflows/publish.yml)
[![Goreport](https://goreportcard.com/badge/github.com/lf-edge/eve)](https://goreportcard.com/report/github.com/lf-edge/eve)
[![Godoc](https://godoc.org/github.com/lf-edge/eve/pkg/pillar?status.svg)](https://godoc.org/github.com/lf-edge/eve/pkg/pillar)
[![DockerHubPulls](https://img.shields.io/docker/pulls/lfedge/eve)](https://hub.docker.com/r/lfedge/eve)
[![slack](https://img.shields.io/badge/slack-eve-brightgreen.svg?logo=slack)](https://lfedge.slack.com/archives/CHMEEC0MP)

EVE aims to develop an open, agnostic and standardized architecture unifying the approach to developing and orchestrating cloud-native applications across the enterprise on-premises edge. It offers users new levels of control through hardware-assisted virtualization of on-prem edge devices. Once installed, EVE has direct access to and control of underlying resources and provides standard APIs that allow more efficient use of resources and can effectively partition hardware to increase workload consolidation and application multi-tenancy.

EVE supports both ARM and Intel architectures and requires hardware-assisted virtualization. While EVE can run on a board as small as a $20 Orange Pi, the sweet spot for its deployment are IoT Gateways and Industrial PCs.

To get its job done, EVE leverages a lot of great open source projects: [Xen Project](https://xenproject.org/), [Linuxkit](https://github.com/linuxkit/linuxkit) and [Alpine Linux](https://alpinelinux.org/) just to name a few. All of that functionality is being orchestrated by the Go microservices available under [pkg/pillar](pkg/pillar). Why pillar? Well, because pillar is the kind of a monolith we need to break out into true, individual microservices under [pkg/](pkg/).

## Download EVE

EVE LTS: [Download latest LTS](https://github.com/lf-edge/eve/releases/latest)

## How to use EVE with a controller (recommended)

EVE-OS can be used with the opensource [Adam controller](https://github.com/lf-edge/adam) by following the instructions at [Eden](https://github.com/lf-edge/eden).

There are also ongoing development of [EVE-OS tutorials](https://github.com/shantanoo-desai/EVE-OS-tutorials).

## How to use/build EVE-OS by itself

You will need [QEMU 3.x+](https://www.qemu.org/), [Docker](https://www.docker.com), [Make](https://www.gnu.org/software/make/)
and [go 1.13+](https://golang.org) installed in your system.

### Use pre-built release binaries

EVE is an agile software project with bi-weekly release schedule. Each release gets tagged
with x.y.z version in Git and a corresponding build is published on [DockerHUB](https://hub.docker.com/r/lfedge/eve).
As is common with Docker releases, EVE also uses version `latest` to designate the latest
official release and `snapshot` to designate the latest build off of master branch.

Since EVE is not just an application, but a compute engine that expects to be deployed
on real (or virtualized) hardware, you can't simply do `docker run` to give it a try.
Instead, you need to use eve Docker container to produce one of the artifacts that
you can then either run on bare metal hardware or deploy on virtualized infrastructure
such as Google Compute Platform (GCP).

EVE Docker container `lfedge/eve:<version>` is used to produce these deployment artifacts.

Try running `docker run lfedge/eve` to get the most up-to-date help message.

The versions in the tag of `lfedge/eve:<version>` contain information as to which hypervisor and target architecture they
support. The options are:

* architecture: `amd64`, `arm64`, `riscv64`
* hypervisor: `kvm`, `xen`, `mini`

Note that not all hypervisors are supported on all architectures.

For example:

* `docker run lfedge/eve:8.11.0-kvm-arm64 <command>`: installer for 8.11.0 using kvm on arm64
* `docker run lfedge/eve:8.11.0-xen-arm64 <command>`: installer for 8.11.0 using xen on arm64
* `docker run lfedge/eve:8.11.0-xen-amd64 <command>`: installer for 8.11.0 using xen on amd64
* `docker run lfedge/eve:8.11.0-mini-riscv64 <command>`: installer for 8.11.0 using mini on riscv64

Note that `<command>` is the appropriate command to run; leave it blank to get the help message.

If you leave off the architecture it will default to whatever architecture you
are running on.

If you just use `snapshot` or `latest`, it will default to the architecture you are running on and the `kvm` hypervisor.

For example:

* `docker run lfedge/eve:8.11.0-kvm <command>`: installer for 8.11.0 using kvm on your architecture
* `docker run lfedge/eve:latest <command>`: installer for latest image using kvm on your architecture

Note that each docker image is built for the architecture for which it runs. Thus `lfedge/eve:8.11.0-kvm-arm64` not only
installs an arm64 EVE image, but the docker image is intended to be run on arm64. If you are running on arm64, e.g. Mac M1,
this works fine. If you are running on an amd64 architecture, docker normally will determine the right architecture.

However, you should indicate to docker your target platform via `--platform`:

```sh
docker run --platform=linux/arm64 lfedge/eve:8.11.0-kvm-arm64
```

or

```sh
docker run --platform=linux/amd64 lfedge/eve:8.11.0-kvm-amd64
```

The above is unnecessary, but does not hurt, if you already are running on the target architecture.

### Install Dependencies

The following steps are required to build and run EVE from source:

#### Get Go

```sh
https://golang.org/dl/
```

#### Get Docker

```sh
https://docs.docker.com/engine/install/
```

Make sure that Docker is up and running on your system. On MacOS just start a docker Application, on Linux make sure docker service is running. Regardless of how you start Docker you can make sure that it is ready for you by running the following command and making sure that it returns both a version of the client AND a version of the server:

```sh
docker version
```

#### Get system dependencies (git, make, qemu, jq)

##### On OSX (using [Brew](https://brew.sh/))

```sh
$ brew install git make jq qemu
```

> **_NOTE:_** (M1 Macs) `qemu` may also require `python3 nettle ninja` to install properly, that is:
>
> ```sh
> $ brew install git make jq python3 nettle ninja qemu
> ```

##### On Ubuntu Linux

```sh
$ sudo apt-get install -y git make jq qemu binfmt-support qemu-user-static \
    qemu-utils qemu-system-x86 qemu-system-aarch64
```

#### Setup Docker

##### Enable execution of different multi-architecture containers

This step is required on **Linux** and is required to create eve bootable images with a different architecture than the host architecture.

```sh
$ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
```

> **_NOTE:_** Should a cross build fail:
>
> For docker to emulate a chip architecture different from the build host, perform this additional step:
>
> ```sh
> $ docker run --privileged --rm tonistiigi/binfmt --install all
> ```
>
> This provides the appropriate `binfmt-support` containers supporting cross execution.  See the [reddit article](https://www.reddit.com/r/docker/comments/ray2wc/running_linuxamd64_images_on_linuxarm64/), [docker hub](https://hub.docker.com/r/tonistiigi/binfmt), private project [page](http://binfmt-support.nongnu.org), or the [source](https://gitlab.com/cjwatson/binfmt-support).

#### Get Project EVE

EVE requires being built in a Git repository (the tools keep looking up git commit IDs). The easiest way is to clone EVE repository from GitHub:

```sh
git clone https://github.com/lf-edge/eve.git
cd eve
```

#### Build Project EVE

Build both the build-tools as well as the live image in the source directory:

```sh
make build-tools
make live
```

This will download the relevant docker images from docker hub and create a bootable
image `dist/<ARCH>/current/live.img`.

Since almost all developer workflow is driven by the Makefile, it may be useful
to familiarize yourself with various Makefile targets that Project EVE offers.
A short summary of those is available by simply running make without any arguments
`make` and a more detailed explanation [is available as part of our documentation](docs/BUILD.md)

> **_NOTE:_** Since the initial build fetches a LOT of bits
> over the network it may occasionally time out and fail. Typically
> re-running `make` fixes the issue. If it doesn't you can attempt a local
> build of all the required EVE packages first by running `make pkgs`
>
> **_NOTE:_** use make parameter "-j" edit number of threads to build faster.
> set number of threads suggestions CPU*2.
> on OSX show number of CPU : `sysctl hw.ncpu`;
> on Ubuntu Linux show number of CPU : `nproc`;

#### Proxies

Building of the various images may require downloading packages from the Internet. If you have direct Internet access, everything will "just work".
On the other hand, if you need to run behind a proxy, you may run into issues downloading. These manifest in two key areas:

* docker: docker needs to download images from the image registries. Configuring your local installation of docker is beyond the scope of this
document, please see [here](https://docs.docker.com/network/proxy/).
* packages: the package updates _inside_ the images running in docker may need to use http/s proxies.

To configure your build process to use proxies, you can set the following environment variables. They will be picked up automatically when running
any `make` commands and used within the building containers. If they are _not_ set, no proxy is set:

* `HTTP_PROXY`
* `HTTPS_PROXY`
* `ALL_PROXY`
* `NO_PROXY`

#### Running in QEMU

Finally run the resulting image in QEMU with some default assumptions:

```sh
make run
```

> **_NOTE:_**  The default QEMU configuration needs 4GB of memory available.
> If you get an error message about being unable to allocate memory, try freeing up some RAM.
> If you can't free up 4GB, you can reduce the memory allocation to qemu from 4096 (4GB) to 2048 (2GB).
> Running QEMU with less than 2GB of memory is not recommended. To run with a different amount of
> memory, provide the desired amount in KB as:

```console
make run QEMU_MEMORY=2048
```

> **_NOTE:_** `make run` launches qemu with the `-bios` option. On some systems, this does not work,
> and you need to run it with the `-pflash` argument (or its equivalent properly configured `-drive`
> instead). To enable pflash, run:

```console
make run PFLASH=true
```

Once the image boots you can interact with it either by using the console
(right there in the terminal window from which make run was executed).
Your shell in the console is connected to the 'host' os. Everything
interesting is actually happening in the pillar container. Use
`eve enter` command to enter it (or if you're comfortable with ctr CLI
from containerd - use that instead).

Once in a container you can run the usual xl commands to start VMs and
interact with Xen.

#### Exitting

To exit out of the QEMU environment, press `Ctrl-A + C` to reach the QEMU console, then `q` to quit.

##### Linux

```sh
$ exit # leave eve
$ poweroff -f # leave qemu
```

### Customizing the Configuration

As described in [BUILD.md](./docs/BUILD.md) and [REGISTRATION.md](./docs/REGISTRATION.md), a booting EVE looks in its config partition to determine:

* the URL to a Controller
* [OPTIONAL] hostnames to add to the `/etc/hosts` file
* certificates to trust
* [OPTIONAL] initial device configuration (aka bootstrap) used only until device is onboarded

When run in an emulator using `make run`, you can override the built-in `/config` partition by passing it the path of a directory to mount as that partition:

```sh
make run CONF_PART=/path/to/partition
```

Note that the directory must exist to be mounted; if not, it will be ignored. The most common use case is a config directory output on the run of [adam](https://github.com/zededa/adam).

While running everything on your laptop with QEMU could be fun, nothing beats real hardware. The most cost-effective option, not surprisingly, is ARM. We recommend two popular board [HiKey](http://www.lenovator.com/product/90.html) and [Raspberry Pi 4](https://www.raspberrypi.org/products/raspberry-pi-4-model-b/). The biggest difference between the two is that on Raspberry Pi (since it doesn't have any built-in flash storage) you won't be able to utlize EVE's installer and you'll have to build a live image. With HiKey you can use a standard EVE's installer. The steps to do both are outlined below:

## How to use on a Raspberry Pi 4 ARM board

Raspberry Pi 4 is a tiny, but capable enough ARM board that allows EVE to run with either Xen or KVM hypervisors. While EVE would run in the lowest memory configuration (1GB) if you plan to use it for actual EVE development we strongly recommend buying a 4GB RAM option.

Since a full Raspberry Pi 4 support is only available in upstream Linux kernels starting from 5.6.0, you'll have to use that bleeding edge kernel for your build. Another peculiar aspect of this board is that it doesn't use a standard [bootloader (e.g. u-boot or UEFI)](https://www.raspberrypi.org/documentation/configuration/boot_folder.md) so we need to trick it into using our own u-boot as UEFI environment. Thankfully, our Makefile logic tries to automate as much of it as possible. Thus, putting it all together, here are the steps to run EVE on Raspberry Pi 4:

1. Make sure you have a clean build directory (since this is a non-standard build) `rm -rf dist/arm64`
2. Build a live image `make ZARCH=arm64 HV=kvm live-raw` (or `make ZARCH=arm64 HV=xen live-raw` if you want XEN by default)
3. Flash the `dist/arm64/current/live.raw` live EVE image onto your SD card by [following these instructions](#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)

Once your Raspberry Pi 4 is happily running an EVE image you can start using EVE controller for further updates (so that you don't ever have to take an SD card out of your board). Build your rootfs by running `make ZARCH=arm64 HV=xen rootfs` (or `make ZARCH=arm64 HV=kvm rootfs` if you want KVM by default) and give resulting `dist/arm64/current/installer/rootfs.img` to the controller.

## How to use on an HiKey ARM board

Unlike Raspberry Pi boards, HiKey boards come with a built-in flash, so we will be using EVE's installer to install a copy of EVE onto that storage. You can follow these steps to prepare your installation media:

1. Start by cloning EVE git repository `git clone https://github.com/lf-edge/eve.git`
2. Build an installer image `cd eve ; make ZARCH=arm64 installer`
3. Flash the `dist/arm64/current/installer.raw` onto the USB stick by [following these instructions](#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)

Since by default HiKey is using WiFi for all its networking, you will also
have to provide SSID and password for your WiFi network. On Mac OS X you
can simply re-insert SD card and edit wpa_supplicant.conf that will appear
on volume called EVE.

At this point you have everything you need to permanently install onto
HiKey's internal flash. This, of course, will mean that if you have anything
else installed there (like a Debian or Android OS) it will be replaced so
make sure to make a backup if you nee to.

Additionally, our installer will try to configure an entry point to the
initial boot sequence via GRUB. Since the only reliable way to do so is
by replacing a file called fastboot.efi in the system boot partition you
need to make sure that you have fastboot.efi present there (since if isn't
there installer will refuse to proceed). The easiest way to check for
all that is to invoke an EFI shell on HiKey. Here's how: put the SD card
into the KiKey, connect HiKey to your serial port, start screen, poweron
HiKey and immediately start pressing `<ESC>` key to trigger EFI shell:

```sh
screen /dev/tty.usbserial-* 115200

[1] fastboot
[2] boot from eMMC
[3] boot from SD card
[4] Shell
[5] Boot Manager
Start: 4
.....
Press ESC in 4 seconds to skip startup.nsh or any other key to continue.

Shell> ls fs2:\EFI\BOOT\fastboot.efi
Shell> setsize 1 fs2:\EFI\BOOT\fastboot.efi
```

NOTE: you only need to execute the last (setsize) command if, for whatever
reason, the previous command doesn't show fastboot.efi present on your
system. Once you've either verified that there's an existing fastboot.efi
(or created a dummy one via the setsize command) you can proceed with
the rest of the installation from the same EFI shell by executing:

```sh
Shell> fs0:\EFI\BOOT\BOOTX64.EFI
```

You will see an installation sequence scroll on screen and the output
that indicates a successful install will look like this:

```sh
[   85.717414]  mmcblk0: p1 p2 p3 p4 p5 p6 p7 p8 p11
[   87.420407]  mmcblk0: p1 p2 p3 p4 p5 p6 p7 p8 p11 p12
[  118.754353]  mmcblk0: p1 p2 p3 p4 p5 p6 p7 p8 p11 p12 p13
[  119.801805]  mmcblk0: p1 p2 p3 p4 p5 p6 p7 p8 p11 p12 p13 p14
[  120.992048]  mmcblk0: p1 p2 p3 p4 p5 p6 p7 p8 p11 p12 p13 p14 p19
[  127.191119] reboot: Power down
(XEN) Hardware Dom0 halted: halting machine
```

At this point you should remove your SD card from HiKey's slot and reboot
the board. If everything went as planned you will boot right into the running
system. One thing that you will notice is that a successful installation sequence
made a backup copy of your existing fastboot.efi under the fastboot.efi.XXX name.
This allows you to restore your HiKey to a pristine state without going through
a full fledged re-flashing sequence.

Alternatively, if you're not quite ready to commit to replace your current OS
on the HiKey, you can try running from the SD card. For that you will have to
put a live system on the SD card, not the installer. Here's how you can do that
on Mac OS X:

```sh
vi conf/wpa_supplicant.conf
  # put your WIFI passwords in and/or add your own networks
make ZARCH=arm64 MEDIA_SIZE=8192 live
sudo dd if=dist/arm64/current/live.raw of=/dev/rdiskXXX bs=1m
```

Then you can boot into a live system from triggering UEFI shell like shown
above and executing exactly the same boot command:

```sh
Shell> fs0:\EFI\BOOT\BOOTX64.EFI
```

## How to use on a Jetson nano 4GB ARM board

In Jetson nano, from January 22, 2021, it became possible to save the u-boot to an internal qspi chip. Following the instructions from the first point and specifying the kernel and u-boot versions in the same way as in EVE, we can run it on the Jetson nano with 4GB of RAM.

1. Follow steps in [instruction](https://github.com/lf-edge/eve/blob/master/boards/nvidia/jetson/) for flash jetson boot flow partitions to qspi.
2. Make sure you have a clean build directory (since this is a non-standard build) `rm -rf dist/arm64`
3. Build a live image `make ZARCH=arm64 HV=kvm live-raw` (Only KVM is supported)
4. Flash the `dist/arm64/current/live.raw` live EVE image onto your SD card by [following these instructions](#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)

## How to use on a i.MX 8MQuad Evaluation Kit ARM board

1. Set SW801 to 1100 for switch boot device to SD card.
2. Build a live image `make ZARCH=arm64 HV=kvm PLATFORM=imx8mq_evk live-raw` (Only KVM is supported)
3. Flash the `dist/arm64/current/live.raw` live EVE image onto your SD card by [following these instructions](#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)

## How to use on an i.MX 8M Plus Phytec phyBOARD-Pollux board

1. Set bootmode switch (S3) to boot device from an SD card (positions 1,2,3,4 set to ON,OFF,OFF,OFF).
2. Build a live image `make ZARCH=arm64 HV=kvm PLATFORM=imx8mp_pollux live-raw` (Only KVM is supported)
3. Flash the `dist/arm64/current/live.raw` live EVE image onto your SD card by [following these instructions](#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)

## How to use on an EPC-R3720 (Advantech, based on i.MX 8M Plus)

This device, from [Advantech](https://www.advantech.com/en-eu/products/880a61e5-3fed-41f3-bf53-8be2410c0f19/epc-r3720/mod_fde326be-b36e-4044-ba9a-28c4c49a25c6), it's an Edge AI Box Computer
based on the NXP i.MX 8M Plus SoC. Three different models are available. EVE was tested and it supports the model EPC-R3720IQ-ALA220. The installation should be performed through the following steps:

1. Set [Boot Select switch (SW1)](http://ess-wiki.advantech.com.tw/view/File:RSB-3720_connector_location_2021-10-21_143853.jpg) to boot device from an SD card (positions 1,2,3,4 set to ON,ON,OFF,OFF).
2. Build a live image `make ZARCH=arm64 HV=kvm PLATFORM=imx8mp_epc_r3720 live-raw` (Only KVM is supported)
3. Flash the `dist/arm64/current/live.raw` live EVE image onto your SD card by [following these instructions](#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)

Note: installation to eMMC is currently not supported. EVE should run from SD Card.

## How to use on an AMD board

The following steps have been tested on Intel UP Squared Board (AAEON UP-APL01) and the bootable USB Disk containing the installer image has been made on Ubuntu 16.04:

1. Start by cloning EVE git repository `git clone https://github.com/lf-edge/eve.git`
2. Build an installer image `cd eve ; make ZARCH=amd64 installer`
3. Flash the `dist/amd64/current/installer.raw` onto the USB stick by [following these instructions](#how-to-write-eve-image-and-installer-onto-an-sd-card-or-an-installer-medium)
4. Now plug the USB Disk on your UP Squared Board and the installer should now replace the existing OS on the UP Squared board with EVE

You will see an installation sequence scroll on screen and the output that indicates a successful install will look like this:

```bash
[10.69716164] mmcblk0:
[11.915943]   mmcblk0: p1
[13.606346]   mmcblk0: p1 p2
[29.656563]   mmcblk0: p1 p2 p3
[30.876806]   mmcblk0: p1 p2 p3 p4
[32.156930]   mmcblk0: p1 p2 p3 p4 p9
NOTICE: Device will now power off. Remove the USB stick and power it back on to complete the installation.
[43.185325]   ACPI: Preparing to enter system sleep state S5
[43.187349]   reboot: Power down
```

At this point you should remove your USB Disk from the UP Squared Board slot and reboot the board. If everything went as planned you will boot right into the running system.

## How to write EVE image and installer onto an SD card or an installer medium

EVE is an very low-level engine that requires producing USB sticks and SD cards that are formatted in a very particular way in order to make EVE install and/or run on a given Edge Node. This, in turn, requires EVE hackers to be comfortable with following instructions which, with a simple typo, can completely destroy the system you're running them on (by overwriting your own disk instead of SD card or a USB stick).

PROCEED AT YOUR OWN RISK

If you want to write any binary artifact foo.bin produced by an EVE build onto an SD card (or any other installation medium) try the following:

Find the device that you will be writing to using

### On Ubuntu

```bash
fdisk -l
```

### On OSX

```bash
diskutil list
```

Now format the USB Disk and run the following commands

### Linux / Ubuntu

```bash
umount /dev/sdXXX
sudo dd if=dist/XXX/foo.bin of=/dev/sdXXX
eject /dev/sdXXX
```

### OSX

```bash
diskutil unmountDisk /dev/sdXXX
sudo dd if=dist/XXX/foo.bin of=/dev/sdXXX
diskutil eject /dev/sdXXX
```

Alternatively the image can be written with tools like [Balena's Etcher](https://www.balena.io/etcher/)

## A quick note on linuxkit

You may be wondering why do we have a container-based architecture for a Xen-centric environment. First of all, OCI containers are a key type of a workload for our platform. Which means having OCI environment to run them is a key requirement. We run them via:

1. Set up the filesystem root using [containerd](https://containerd.io)
1. Launch the domU using Xen via `xl`

In addition to that, while we plan to build a fully disagregated system (with even device drivers running in their separate domains) right now we are just getting started and having containers as a first step towards full disagreagation seems like a very convenient stepping stone.

Let us know what you think by filing GitHub [issues](https://github.com/lf-edge/eve/issues/new/choose), and feel free to send us pull requests if something doesn't quite work.

## License

Distributed under the Apache License 2.0. See [LICENSE.txt](https://github.com/lf-edge/eve/blob/master/LICENSE) for more information.
