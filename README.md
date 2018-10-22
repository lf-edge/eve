# Zenbuild

zenbuild is a LinuxKit based builder for Xen-centric platforms targeting x86 and ARM architectures

How to use:

You will need qemu (https://www.qemu.org/), Docker (https://www.docker.com) 
and go 1.9+ (https://golang.org) installed in your system.

Note, that since Linuxkit and manifest-tool are evolving pretty rapidly, we're
vendoring those under build-tools/src. This means you don't have to have them
locally installed, but it also means your first build time will be much longer.

If you're on MacOS the following steps should get you all the dependencies:

  1. Get Docker:

  ```
  https://store.docker.com/editions/community/docker-ce-desktop-mac
  ```
  2. Make sure brew is installed:

  ```
  https://brew.sh/
  ```
  3. Brew install qemu.

  ```
  $ brew install qemu
  ```

Make sure that Docker is up and running on your system. On MacOS just start a docker Application, on Linux make sure docker service is running. Regardless of how you start Docker you can make sure that it is ready for you by running the following command and making sure that it returns both a version of the client AND a version of the server:

```
docker version
```

zenbuild requires beeing built in Git repository (the tools keep looking up git commit IDs). The easiest way is to clone zenbuild repository from GitHub:
```
git clone https://github.com/zededa/zenbuild.git
cd zenbuild
```

Build both the build-tools as well as the fallback image in the source directory:

```
make build-tools
make fallback.img
```
This will download the relevant dockers from docker hub and create a bootable
image 'fallback.img'.

Please note that not all containers will be fetched from the docker
hub. mkimage-raw-efi in particular will be built.

Also, keep in mind that since the initial build fetches a LOT of bits
over the network it may occasionally time out and fail. Typically
re-running make fixes the issue. If it doesn't you can attempt a local
build of all the required zenbuild packages first by running:

```
make pkgs
```

Finally run the resulting image by typing `make run`. This will launch
qemu with some default assumptions. Make sure to wait for the GRUB menu
to show up and then pick the 2nd option (otherwise image will hang).

Once the image boots you can interact with it either by using the console
(right there in the terminal window from which make run was executed).
Your shell in the console is connected to the 'host' os. Everything
interesting is actually happening in the zededa-tools container. Use
`zen enter` command to enter it (or if you're comfortable with ctr CLI
from containerd - use that instead).

Once in a container you can run the usual xl commands to start VMs and
interact with Xen.

While running everything on your laptop with qemu could be fun, nothing
beats real hardware. The most cost-effective option, not surprisingly,
is ARM. We recommend using HiKey board (http://www.lenovator.com/product/90.html).
Once you aquire the board you will need to build an image, flash it onto
the SD card and tell the UEFI bootloader to boot the GRUB payload from
the SD card. Here's what you need to do:
```
cp images/rootfs.yml.in.hikey images/rootfs.yml.in
vi blobs/wpa_supplicant.conf
  # put your WIFI passwords in and/or add your own networks
make ZARCH=aarch64 MEDIA_SIZE=1024 fallback_aarch64.raw
sudo dd if=fallback_aarch64.raw of=/dev/rdiskXXX bs=1m
``` 

Now put the SD card into the KiKey, connect HiKey to your serial port,
start screen and poweron HiKey:
```
screen /dev/tty.usbserial-* 115200

[1] fastboot
[2] boot from eMMC
[3] boot from SD card
[4] Shell
[5] Boot Manager
Start: 4
.....
Press ESC in 4 seconds to skip startup.nsh or any other key to continue.
Shell> fs0:\EFI\BOOT\BOOTAA64.EFI

Finally pick the last menu item in GRUB saying
  LinuxKit Image on HiKey/ARM64
```

As an aside, you may be wondering why do we have a container-based
architecture for a Xen-centric environment. First of all, OCI containers
are a key type of a workload for our platform. Which means having
OCI environment to run them is a key requirement. We do plan to run them
via Stage 1 Xen (https://github.com/rkt/stage1-xen) down the road, but 
while that isn't integrated fully we will be simply relying on containerd.
In addition to that, while we plan to build a fully disagregated system 
(with even device drivers running in their separate domains) right now
we are just getting started and having containers as a first step towards
full disagreagation seems like a very convenient stepping stone. 

Let us know what you think by filing GitHub issues, and feel free to 
send us pull requests if something doesn't quite work.
