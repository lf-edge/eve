# Ubuntu

The basics of using the build system are in [BUILD.md](./BUILD.md).
It is highly recommended you start there. This document describes how to update eve-ubuntu.

[Ubuntu](https://ubuntu.com) is the base distribution used for software
dependencies in EVE: its `.deb` packages are the source of binary
artifacts, and its `dpkg` database is where the SBOM of every container is
read from.

A base image `lfedge/eve-ubuntu` is composed from the source in
[pkg/ubuntu](../pkg/ubuntu/) and is used as the `FROM` image for all
other packages in [pkg/](../pkg/).

As long as eve-ubuntu _already_ contains the packages you need, you simply
reference it in your Dockerfile:

```Dockerfile
FROM lfedge/eve-ubuntu:<hash>
```

For example, as of this writing, the [uefi Dockerfile](../pkg/uefi/Dockerfile) begins:

```Dockerfile
FROM lfedge/eve-ubuntu:9a6ebfad80ca4d18950553f8bf2c01a068869805 AS build
```

If you need a package that is not in eve-ubuntu, you need to update eve-ubuntu itself.

## What eve-ubuntu provides

Ubuntu's archive is a moving target: `apt-get install curl` gives whatever
version the `-updates` and `-security` pockets carry today, and a package
version that was there yesterday may be gone tomorrow. That is not acceptable
for a build that has to be reproducible, so eve-ubuntu pins everything to one
timestamp of the [Ubuntu snapshot service](https://snapshot.ubuntu.com):
`UBUNTU_SNAPSHOT` in [pkg/ubuntu/Dockerfile](../pkg/ubuntu/Dockerfile).
The builder, the bootstrap of the container rootfs and the package mirror are
all resolved against that timestamp, so rebuilding the image yields the same
package set, and every consumer sees the same bits until the timestamp or the
package lists change.

The image is a single stage that contains:

* the **builder**: an Ubuntu system with the toolchains (`build-essential`,
  Ubuntu's `golang-go`, cmake, autotools, ...), ready to compile things.
* **`/out`**: a minimal Ubuntu rootfs (`debootstrap --variant=minbase`,
  slimmed down) which becomes the root filesystem of the container that a
  package produces. `eve-ubuntu-deploy.sh` installs packages into it, and the
  package's Dockerfile copies it into a `FROM scratch` stage.
* **`/mirror/archives`**: a local apt repository holding the `.deb` files of
  the transitive dependency closure of every package listed under
  [pkg/ubuntu/mirrors](../pkg/ubuntu/mirrors/). Both the builder and `/out`
  install from this mirror only, which is why every other package builds with
  `network: no`.
* a few helper scripts in `/bin`, described below.

### Helper scripts

* `eve-ubuntu-deploy.sh` installs `BUILD_PKGS` (and `BUILD_PKGS_<arch>`) into
  the builder and `PKGS` (and `PKGS_<arch>`) into `/out`. apt runs in the
  builder for both: with `-o Dir=/out` it uses the sources, lists and cache
  below `/out`, and with `DPkg::Chroot-Directory=/out` it chroots into `/out`
  before calling dpkg, so no bind mounts are needed. When it is done, the apt
  source of `/out` points at the snapshot again (`sources.list.upstream`), so a
  container with network access can still `apt-get install` tools.
* `register-sbom-pkg.sh` records a package built from source in
  `/out/var/lib/dpkg/status.d/<name>` (one file per package, the distroless
  convention) plus a machine readable copyright file, so that syft lists it in
  the SBOM. Every Dockerfile that `ADD`s external sources must call it, see
  [tools/check-sbom-coverage.sh](../tools/check-sbom-coverage.sh).
* `merge-sbom-db.sh` merges the `/var/lib/dpkg/status` files of several stages
  into one, keeping one record per package, for images assembled from more than
  one eve-ubuntu stage (pillar, debug).
* `copy-with-libs.sh` copies files out of a rootfs together with the shared
  libraries they need, resolved with `lddtree` (pax-utils, part of the
  builder), and the dpkg records of the
  packages they came from. It is how images that cannot carry a whole Ubuntu
  rootfs are assembled: the `init:` images that are overlaid onto the EVE host
  rootfs (dom0-ztools, udev, kexec; the host rootfs itself is pkg/init),
  and the bpftrace runtime shipped by the debug container. It never recreates
  the merged-/usr symlinks of Ubuntu (`/bin -> usr/bin`, ...): a symlink in
  place of an existing directory does not extract onto the host rootfs. With
  `-m` the files are meant for another Ubuntu based container (merged /usr,
  loader path already present) and no loader alias directory is created.
* `eve-mkinitramfs.sh` builds a busybox based initramfs out of a rootfs, used
  for the live/installer initrd (mkimage-raw-efi), the ISO initrd
  (mkimage-iso-efi) and the shim VM initrd (xen-tools). `/bin/sh` of the
  initramfs is busybox, so the init script of Alpine's mkinitfs runs unchanged.
* `go-compile.sh` lints, tests and installs a Go program as a static binary.

### Rules

```Dockerfile
# ALWAYS do this:
FROM lfedge/eve-ubuntu:<hash> AS build
ENV PKGS="curl"
ENV BUILD_PKGS="gcc"
RUN eve-ubuntu-deploy.sh
...
FROM scratch
COPY --from=build /out/ /

# NEVER do this:
FROM ubuntu:resolute
RUN apt-get update && apt-get install -y curl
```

Packages are named exactly as they are in Ubuntu (`packages.ubuntu.com`).
Recommends and Suggests are never installed; what a package needs must be in
its `Depends`, or be listed explicitly.

Some Ubuntu builds of familiar tools behave differently from Alpine's and the
packages account for that: util-linux's `lsblk` is linked with libudev and
reads `PARTUUID`, `PARTLABEL` and friends from the udev database, so the udev
package keeps eudev's block device rules that import the blkid properties
(zboot and pillar depend on those columns); `sgdisk` lives in `/usr/sbin`;
`sshd` needs `/run/sshd`; `bsdtar` wants a UTF-8 locale; and mtools needs the
`IBM850` iconv module, which `/out` therefore keeps. `ctr` and `runc` still
come from linuxkit's Alpine built containerd and runc images, so a container
that executes the bind-mounted `ctr` (debug, watchdog) installs Ubuntu's
`musl` package to get the `/lib/ld-musl-*.so.1` loader.

The host rootfs (pkg/init) is `/out` as well, with busybox-static for PID 1
(busybox init runs linuxkit's `/etc/inittab`), the hotplug helper and the
applets the init scripts expect, plus linuxkit's init programs built from the
commit `linuxkit/init:v1.3.0` came from. Since every container carries the
same `/out`, the squashfs stores the host's copy once with theirs. Ubuntu's
merged-/usr symlinks are replaced by real `/bin`, `/sbin`, `/lib` and
`/lib64` directories (the kernel's modules, the firmware and the init overlays
add real directories there), each mirroring its `/usr` counterpart entry by
entry, so both spellings of a path work: the dynamic loader where the
binaries name it, dpkg's alternatives (`/bin/nc.openbsd`), the Ubuntu tools
under `/bin` whatever PATH's order (busybox's login puts `/bin` before
`/usr/bin`). The busybox applets fill in where Ubuntu has no tool of the
name. `/bin/sh` is busybox ash, not dash: the init scripts use ash features
(`${var/pat/rep}`) that dash lacks, and the console shell keeps its history
and line editing. Debian builds busybox as a *standalone shell*: ash runs
its own applet for every command name it has (`ps`, `grep`, `sed`, `nc`,
`run-parts`, `mount`, ...) whatever PATH says, so the host's scripts see
busybox's tools exactly as they did on Alpine, and a program of the same
name from an Ubuntu package is only reached by a path with a slash
(`/usr/bin/nc`, which the eve CLI uses for the `-z` probe Debian's busybox
nc lacks). pkg/init therefore ships linuxkit's Alpine-style `/etc/profile`
in place of Ubuntu's, whose `run-parts --list` would hit busybox's
run-parts and never source `/etc/profile.d`. `pgrep` and `pkill` come from
procps, `agetty` from util-linux, and the `musl` package provides the loader
of `ctr` and `runc`, which are still linuxkit's Alpine builds. Nothing else
of linuxkit's getty image is needed: EVE's own `rungetty.sh` and `001-getty`
live in dom0-ztools; `/etc/securetty` comes from the image manifests.

The differences that bit during the port and are easy to reintroduce:

* `/out` has no busybox. Every applet an Alpine container had for free is a
  package now (`procps` for ps/pgrep/pkill, `net-tools`, `lsof`, `rfkill`,
  `util-linux-extra` for wdctl, `bridge-utils`, `kmod`, ...). `reboot` and
  `poweroff` come from `busybox-static` plus `/usr/sbin` links in the
  containers that reboot the device, so plain `reboot` keeps signalling the
  linuxkit init as it did on Alpine. Audit every command a package execs
  (`base.Exec`, `exec.Command`, scripts) against the image before relying on
  a boot smoke test; a missing command fails only when that path runs.
* Same name, different behaviour: procps `pgrep`/`pkill` match the process
  name (comm) unless `-f`, busybox matched argv[0], so `pgrep /usr/bin/foo`
  silently matches nothing (use `pgrep -x foo` or `-f`); procps `ps` without
  options shows only the caller's session (`ps -ef`); `chronyc` drops to
  `_chrony` before talking to the daemon, so chronyd runs as `_chrony` too
  (its Ubuntu default) and any client socket it must answer has to be
  writable for that user (zedagent's is 0666, as chronyc's own); Debian's busybox
  lacks `brctl show`; `awk` is mawk; kmod's `modprobe` looks up built-in
  modules in the binary indexes, where the eve-kernel's `modules.builtin.bin`
  does not resolve them, so `modprobe usb_storage` fails where busybox
  succeeded.
* Size: the kvm rootfs is 291 MiB against 282 MiB on Alpine. The glibc
  builds of the same tools are simply larger (coreutils, openssh, iproute2,
  iptables, libssl, glib, wpa_supplicant ...). Stripping the three binaries
  that shipped with their symbol tables on both bases (mmagent, node_exporter,
  runc) took 19 MiB off and brought the image back under the 300 MiB
  IMGA/IMGB partitions of devices installed before EVE 10.2.0 (10.2.0 and
  later use 512 MiB or more). `ROOTFS_MAXSIZE_MB` in the Makefile is 295
  (master: 290) so that margin stays visible. Removing everything a container
  never runs (perl, the dpkg and debconf tools, docs, locales, fonts, unused
  qemu and swtpm helpers) would give another 8 MiB; the firmware tree is the
  far bigger lever (53 MiB of the image, 39 of them iwlwifi versions the
  kernel never loads and board-only blobs), but that is not an Ubuntu matter.
* Names: gid 65534 is `nogroup`, not `nobody` (pillar adds a `nobody` group
  alias for dnsmasq); `mkisofs` does not exist, only `xorrisofs` (pillar links
  it); `/var/run` is a symlink to `/run`.
* `busybox --install -s` places applets by busybox's own idea of bin/sbin:
  the debug container removes the `logread` links so the host's logread bound
  into `/usr/bin` wins in root's PATH.
* Assertions: GCC 15's libstdc++ enables `_GLIBCXX_ASSERTIONS` by itself for
  any compile without an optimisation level, which Alpine's gcc 14 did not.
  A CMake project built without `CMAKE_BUILD_TYPE` (bpftrace in
  `pkg/bpftrace`, on master too; bcc picks Release itself) therefore aborts
  at run time where it used to get away with undefined behaviour, such as
  dereferencing a null `unique_ptr` or an empty `optional` (bpftrace patches
  0005 and 0006). Fix the code, or set a build type if an optimised build is
  wanted.

## Adding new packages to eve-ubuntu

The lists under [pkg/ubuntu/mirrors/resolute](../pkg/ubuntu/mirrors/resolute/)
name the top-level packages whose dependency closure the mirror holds:

* `main`: for every architecture
* `main.amd64`, `main.arm64`, `main.riscv64`: architecture specific, e.g. the
  cross toolchains or `iucode-tool`

To add a package:

1. Add its name to the right list. Keep the lists grouped and sorted; one
   package per line, `#` starts a comment.
1. Rebuild eve-ubuntu: `make pkg/ubuntu`. The build needs network access and
   takes a while: it bootstraps `/out` and downloads the mirror. If the
   package does not exist for an architecture, the build fails for that
   architecture.
1. Reference the new hash. `linuxkit pkg show-tag pkg/ubuntu` prints it once
   the change is committed; every consumer's `FROM lfedge/eve-ubuntu:<hash>`
   has to move to it. `make check-docker-hashes-consistency` lists the stale
   references and [tools/bump_dockerfiles.pl](../tools/bump_dockerfiles.pl)
   rewrites them.
1. Use the package in your Dockerfile's `PKGS` or `BUILD_PKGS`.

The hash of eve-ubuntu is the git tree hash of `pkg/ubuntu`, so any change
there, including this document's neighbours like `dnstest`, means a new hash
and a rebuild of every package.

## Moving to a new snapshot or release

`UBUNTU_SNAPSHOT` selects the archive state. Bumping it picks up the
security and bug fix updates Ubuntu published since; the date must be one for
which an `ubuntu:resolute-<date>` image exists, because the builder image
itself already contains packages from `-updates` and `-security`, and the
snapshot must not be older than them. A new Ubuntu release means a new
`UBUNTU_RELEASE`, a new directory under `mirrors/` and a review of package
names that changed between releases.

[tools/compare-eve-ubuntu-mirror.sh](../tools/compare-eve-ubuntu-mirror.sh)
shows which package versions differ between two eve-ubuntu images, e.g.
between a local build and the one master uses.

## Keeping the images small

Every container carries the `/out` rootfs. Identical files are stored once in
the squashfs of the EVE rootfs image, so the base costs its size once, but
everything a package installs on top of it counts. `/out` therefore has no
documentation, manual pages or locales (`dpkg-nodoc.cfg`), no apt, and the
Dockerfiles copy only what a container needs when the whole rootfs is not
needed (`copy-with-libs.sh`). `make rootfs` fails when the image exceeds
`ROOTFS_MAXSIZE_MB` of the top-level Makefile.

## The dnsmasq test

[pkg/ubuntu/dnstest](../pkg/ubuntu/dnstest/) runs, as part of `make test`,
a test against the dnsmasq of the eve-ubuntu image of the checkout, the one
pillar installs. It builds its container from the image in the linuxkit
cache, so `make pkg/ubuntu` has to have run first.

## Appendix

### A package made of Ubuntu packages only

```Dockerfile
FROM lfedge/eve-ubuntu:<hash> AS build
ENV PKGS="mtools dosfstools"
RUN eve-ubuntu-deploy.sh

COPY make-config /out/

FROM scratch
COPY --from=build /out /
ENTRYPOINT [ "/make-config" ]
```

### A package that builds something from source

```Dockerfile
FROM lfedge/eve-ubuntu:<hash> AS build
ENV BUILD_PKGS="make gcc libc6-dev liblzma-dev"
ENV PKGS="liblzma5"
RUN eve-ubuntu-deploy.sh

ADD https://example.org/foo-1.0.tar.gz /tmp/foo.tar.gz
WORKDIR /tmp/foo
RUN tar -xzf /tmp/foo.tar.gz --strip-components=1 && ./configure --prefix=/usr && make && make DESTDIR=/out install
# mandatory for foo to be included in the SBOM
RUN register-sbom-pkg.sh -n foo -v 1.0 -l MIT -u https://example.org/foo

FROM scratch
COPY --from=build /out/ /
```
