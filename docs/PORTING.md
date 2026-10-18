# Bringing EVE up on a new CPU architecture

EVE currently support x86 and ARM Edge Nodes. It works best when hardware assisted virtualization is available, but it can run with reduced functionality on pretty much anything supported by the Linux kernel. Most of the time, bringing EVE up on a new hardware configuration requires [peripheral hardware enablement](HARDWARE-BRINGUP.md) but in rare cases it may actually require supporting a brand new CPU model. The later consists of the following steps:

1. Prerequisites
2. Porting Ubuntu packages EVE depends on to the new CPU
3. Hooking up new CPU emulation environment to Makefile and GitHub workflows
4. Porting firmware, low-level bootloader and GRUB on the new CPU
5. Porting Linux kernel to the new CPU
6. Porting user-space EVE containers to the new CPU

## 1. Prerequisites

First of all, we are assuming that GCC and/or LLVM toolchain and Golang toolchain already provide support for the target CPU. We are also assuming that cross-compilation for both is an option (if either of these assumptions is broken -- you will have to engage in a heavy development effort bringing these toolchain up to speed with the target architecture). We are also assuming that qemu already supports the target CPU in either system or user mode.

## 2. Porting Ubuntu packages EVE depends on to the new CPU

If you're lucky, Ubuntu may already be providing support for the new CPU architecture through [Ubuntu Ports](https://ports.ubuntu.com) and the [Ubuntu snapshot service](https://snapshot.ubuntu.com), which is what [pkg/ubuntu](../pkg/ubuntu) builds `lfedge/eve-ubuntu` from. If not, you need to start bootstrapping Ubuntu (or, more realistically, Debian, from which Ubuntu derives its ports) for the new architecture yourself, which is a heavy development effort and out of scope of this document.

The full list of Ubuntu packages required by EVE is available under [pkg/ubuntu/mirrors](../pkg/ubuntu/mirrors) and while it is not long, their dependency closure is a few hundred packages, all of which must exist for the new architecture. Compare the lists against the `Packages` index of the port: `pkg/ubuntu` fails to build for an architecture that misses any of them, which tells you what still has to be ported or dropped (architecture specific packages go to a `main.<arch>` list).

## 3. Hooking up new CPU emulation environment to Makefile and GitHub workflows

The rest of the porting journey will be taken step-by-step, but it helps when each step can be facilitated by the Makefile infrastructure and CI/CD workflows so that everything is fully automated. The first package that both Makefile and CI/CD infrastructure needs to know how to publish is `pkg/ubuntu`, which provides the build environment and the container rootfs for every other package. You will need to tweak `pkg/ubuntu/Dockerfile` so that debootstrap and the mirror resolve for the new architecture (`TARGETARCH` must be a `dpkg` architecture name) and to add the architecture to the matrix in [.github/workflows/build-ubuntu-base.yml](../.github/workflows/build-ubuntu-base.yml).

The last statement in the series is used to constrain the initial content of the 2nd package that must be available from Day 1: `pkg/eve`. That is the final package that all of EVE users interact with in order to produce various images.

Next you should adjust the packages `PKGS` in [Makefile](../Makefile) you need to make available from the get go is `pkg/ubuntu` plus whatever maybe required to enable `pkg/eve`. These packages are typically very easy to port and they constitute a good testcase for making sure that `pkg/ubuntu` is actually functional.

To sum it up, here's what the above variables do:

* `PKGS` the list of the packages that is ready to be built for a new architecture (bare minimum is pkg/ubuntu and pkg/eve)
* `ZARCH` explicit selection of the architecture to build for (unless you don't have to do a cross-build)

## 4. Porting firmware, low-level bootloader and GRUB on the new CPU

Once `pkg/ubuntu` is available for the target CPU architecture the first 3 EVE packages to be made available next are always [uefi](../pkg/uefi), [grub](../pkg/grub) and possibly [u-boot](../pkg/u-boot). Making these packages available will allow you to start qemu in system mode and have the barebones execution environment that will get you all the way to loading Linux kernel. The Makefile target that needs to be enabled once all these packages are available is `make run-grub` and it typically requires update to the architecture specific settings of how qemu is command line is produced by Makefile rules (see various `QEMU_*` variables in the Makefile).
