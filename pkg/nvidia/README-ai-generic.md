# NVIDIA x86 dGPU Userland (`PLATFORM=ai-generic`)

## Introduction

The `ai-generic` variant of this package stages the NVIDIA x86 discrete-GPU
(dGPU) **userland** - `libnvidia-compute`, `libnvidia-cfg1`, `nvidia-utils`,
`nvidia-compute-utils`, `libnvidia-common`, and the CDI tools from
`nvidia-container-toolkit-base` - into `/opt/vendor/nvidia` in EVE's rootfs.
It is amd64 only; on arm64 and riscv64 the variant is an empty image.
`build-ai-generic.yml` selects it, and its stages in the `Dockerfile` are
separate from the Jetson ones described in [README.md](README.md).

## Why the kernel module and firmware live elsewhere

This variant intentionally does **not** ship the NVIDIA kernel driver module
or the GSP firmware. The eve-kernel build has `CONFIG_MODULE_SIG_FORCE` set,
which means any kernel module has to be signed by the key that only exists
inside the kernel build itself - a module built or signed anywhere else will
be rejected at `insmod` time. So:

* The NVIDIA open GPU kernel module is built and signed as part of the
  **eve-kernel** image (see `eve-kernel/Makefile.eve`).
* The GSP firmware ships in the same eve-kernel image, under
  `/lib/firmware/nvidia/<version>/`.
* This variant ships only the matching **userland**.

## The three pieces must be the exact same version

NVIDIA pins the kernel module, the userland, and the GSP firmware to each
other by exact version equality - mixing versions across these three is not
supported and will generally fail to load or misbehave. Concretely, that
means `NVIDIA_DRIVER_VERSION` (and `NVIDIA_DRIVER_BRANCH`) in the `dgpu-amd64`
stage of this package's `Dockerfile` **must match** the
`NVIDIA_DRIVER_VERSION` / `NVIDIA_DRIVER_BRANCH` used in `eve-kernel`'s
`Makefile.eve`. When bumping one, bump the other in the same change.

## Compute-only, headless

This build deliberately excludes the display/OpenGL stack:

* No `libnvidia-gl-*` (the ~519MB OpenGL/display library set).
* No `libnvidia-decode-*` (NVDEC video decode; pulls X11 libs we don't want
  in an otherwise headless image).
* No `xserver-xorg-video-nvidia-*`, `nvidia-settings`, or `nvidia-xconfig`.

Only `nvidia` and `nvidia_uvm` kernel modules are loaded by
`init.d/nv-init.sh`; `nvidia_modeset` and `nvidia_drm` (the display/KMS
modules) are never loaded.

## Layout

* `/opt/vendor/nvidia/dist/` - the extracted `etc/`, `lib/`, `sbin/` and `usr/`
  trees from the downloaded `.deb` packages, with their original paths
  preserved.
* `/opt/vendor/nvidia/bin/` - stable entry points (symlinks into `dist/`) for
  `nvidia-ctk`, `nvidia-cdi-hook`, `nvidia-container-runtime`, `nvidia-smi`
  and `nvidia-persistenced`, plus `ldconfig-glibc` (a copy of Ubuntu's
  ldconfig for the CDI update-ldcache hook).
* `/opt/vendor/nvidia/eve-platform` - `ai-generic`, as the Jetson variants
  write theirs. kube-init stages the device plugin manifest pkg/kube ships for
  this platform, and labels the node `eve.lfedge.org/nvidia-gpu=true` while
  its GPU is usable.
* `/opt/vendor/nvidia/init.d/nv-init.sh` - run by pillar at init; loads the
  compute kernel modules, ensures `/dev/nvidia0` exists, and generates (once)
  the CDI spec at `/run/cdi/nvidia.yaml`.

## SBOM

Every deb whose contents ship is registered with `register-sbom-pkg.sh` (name
and version from the deb; NVIDIA driver packages as `proprietary`, the
container toolkit as `Apache-2.0`), plus `libc-bin` for `ldconfig-glibc`.

## Downloads

The debs come from Launchpad's per-file URLs rather than the Ubuntu archive
pool, because the pool deletes superseded versions and a pinned driver
version would stop building at Ubuntu's next driver update. Each one is
fetched with `ADD --checksum=sha256:...`, so a driver or toolkit bump changes
a URL and its checksum together, a rebuild reproduces the same userland or
fails, and the build needs no network in `RUN`. The stages run on eve-alpine:
`dpkg-deb` extracts the debs, calling `zstd` for Ubuntu's `data.tar.zst`.

## References

* [Container Device Interface](https://github.com/cncf-tags/container-device-interface)
* [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-container-toolkit)
* `eve-kernel/Makefile.eve` - the kernel-side half of the version pin.
* [README.md](README.md) - the Jetson variants of this package.
