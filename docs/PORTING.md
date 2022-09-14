# Bringing EVE up on a new CPU architecture

EVE currently support x86 and ARM Edge Nodes. It works best when hardware assisted virtualization is available, but it can run with reduced functionality on pretty much anything supported by the Linux kernel. Most of the time, bringing EVE up on a new hardware configuration requires [peripheral hardware enablement](HARDWARE-BRINGUP.md) but in rare cases it may actually require supporting a brand new CPU model. The later consists of the following steps:

1. Prerequisites
2. Porting Alpine packages EVE depends on to the new CPU
3. Hooking up new CPU emulation environment to Makefile and GitHub workflows
4. Porting firmware, low-level bootloader and GRUB on the new CPU
5. Porting Linux kernel to the new CPU
6. Porting user-space EVE containers to the new CPU

## 1. Prerequisites

First of all, we are assuming that GCC and/or LLVM toolchain and Golang toolchain already provide support for the target CPU. We are also assuming that cross-compilation for both is an option (if either of these assumptions is broken -- you will have to engage in a heavy development effort bringing these toolchain up to speed with the target architecture). We are also assuming that qemu already supports the target CPU in either system or user mode.

## 2. Porting Alpine packages EVE depends on to the new CPU

If you're lucky, Alpine Linux may be already providing support for the new CPU architecture. If not, you need to start bootstrapping the Alpine environment yourself. This is typically done by first cross-compiling enough of Alpine environment using [aports bootstrap.sh script](https://github.com/alpinelinux/aports/blob/master/scripts/bootstrap.sh) on a commodity x86 architecture (the more CPUs you have the faster it will go) and then proceeding with building an emulation environment to compile the rest of the packages EVE depends upon. The later step is required because Alpine Linux (unlike more traditional embedded Linux distributions) doesn't actually focus on cross-compilation of most of the packages aside from the ones required from bootstrap.

The full list of Alpine packages required by EVE is available under [pkg/alpine](../pkg/alpine) and while it is not long, it actually requires twice as many packages available during the build phase so your bootstrapping efforts may take some time. The most convenient way to move from a cross-compiling `bootstrap.sh` phase of Alpine bringup to bringing up the rest of the packages is to use [qemu user emulation mode](https://qemu.readthedocs.io/en/latest/user/index.html) under either Docker desktop or [proot](https://proot-me.github.io/). Both of these will require an image of a filesystem that is complete enough to run basic Unix commands. A good place to star assembling this image into a single tarball is the output packages from the `bootstrap.sh`. Note, however, that you may need to manually untar them and put everything in just the right order yourself. Taking a look at what files comprise a typical Alpine docker image `docker pull alpine:latest` will give you a hint at what's required. Here's a minimal list of packages that need to appear in that filesystem image: `abuild curl tar make linux-headers patch g++ git gcc ncurses-dev autoconf`.

Once you assembled your new image and launched a shell inside of that filesystem, you can start using standard Alpine's [abuild](https://wiki.alpinelinux.org/wiki/Abuild_and_Helpers) tools with the source code from [aports](https://github.com/alpinelinux/aports) to build the remainder of the required packages. The process involves cd'ing into `{main,community,testing}/package-name` folder in the aports tree, sometimes editing APKBUILD script and running `abuild -r`. Your resulting packages will get deposited under `$HOME/packages` provided that you're using a standard Alpine build environment with a dedicated builder user. A minimal set of steps required to setup such an environment is captured in the following [Dockerfile](../build-tools/src/scripts/Dockerfile.alpine.bootstrap). That same file also contains a skeleton of a dummy APKBUILD file that one can use to stub-out packages that are required by `pkg/alpine` but are not available yet.

Once you have an MVP collection of Alpine packages you need to upload them plus the tarball of your build environment to some publicly available https endpoint (AWS S3 buckets work great).

## 3. Hooking up new CPU emulation environment to Makefile and GitHub workflows

The rest of the porting journey will be taken step-by-step, but it helps when each step can be facilitated by the Makefile infrastructure and CI/CD workflows so that everything is fully automated. The first package that both Makefile and CI/CD infrastructure needs to know how to publish is `pkg/alpine-base` which will provide a build environment for `pkg/alpine`. You will need to tweak `pkg/alpine-base` to use your repository and minirootfs filesystem alongside with official published [releases](https://alpinelinux.org/releases/) as official docker image of alpine may not exist for your architecture. `pkg/alpine` should be based on top of your updated `pkg/alpine-base` to download and cache the set of packages.

The last statement in the series is used to constrain the initial content of the 2nd package that must be available from Day 1: `pkg/eve`. That is the final package that all of EVE users interact with in order to produce various images.

Next you should adjust the packages `PKGS` in [Makefile](../Makefile) you need to make available from the get go is `pkg/alpine` plus whatever maybe required to enable `pkg/eve`. These packages are typically very easy to port and they constitute a good testcase for making sure that `pkg/alpine` is actually functional.

To sum it up, here's what the above variables do:

* `PKGS` the list of the packages that is ready to be built for a new architecture (bare minimum is pkg/alpine-base, pkg/alpine and pkg/eve)
* `ZARCH` explicit selection of the architecture to build for (unless you don't have to do a cross-build)

## 4. Porting firmware, low-level bootloader and GRUB on the new CPU

Once `pkg/alpine` is available for the target CPU architecture the first 3 EVE packages to be made available next are always [uefi](../pkg/uefi), [grub](../pkg/grub) and possibly [u-boot](../pkg/u-boot). Making these packages available will allow you to start qemu in system mode and have the barebones execution environment that will get you all the way to loading Linux kernel and potentially type-1 hypervisors like Xen. The Makefile target that needs to be enabled once all these packages are available is `make run-grub` and it typically requires update to the architecture specific settings of how qemu is command line is produced by Makefile rules (see various `QEMU_*` variables in the Makefile).
