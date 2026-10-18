# Source Tracing

As an open source project, it is important for all of the sources for EVE to be open and available. While for some having this repository
may suffice, EVE sets higher standards. Specifically, EVE desires that it be possible to trace from a given EVE image back to the
sources of all software used in that binary compilation of EVE.

This is done for several purposes:

* Debugging, where knowledge of the precise source used is critical.
* Auditing, where users auditing a particular distribution require confidence that they are reviewing precisely the correct source.
* License compliance, where several licenses, notably the GPL family, require either distribution of source or links to source when distributing binary artifacts.

This document will describe how to trace from a given compiled distribution of EVE all the way back to all sources.

The stages are:

1. Binary to source commit
1. Binary to builder configuration
1. Container images to container sources
1. Container sources to contents:
   * Local content
   * Go modules
   * External sources
   * Ubuntu packages

## Binary to source commit

EVE is distributed in several formats.

* Docker Images at [Docker Hub](https://hub.docker.com/r/lfedge/eve/). These are tagged with the version or commit of the image, as well as the architecture and hypervisor.
* Release artifacts [on github](https://github.com/lf-edge/eve/releases). For example, [version 8.10.0](https://github.com/lf-edge/eve/releases/tag/8.10.0).

If you are using a particular artifact, use the version provided to get your release version.

* For Docker images with a [semver](https://semver.org/) tag, use the tag. For example, for `lfedge/eve:8.10.0-kvm`, use `8.10.0`.
* For Docker images with a hash commit, use the commit. For example, for `lfedge/eve:0.0.0-master-5729285b-kvm-arm64`, use `5729285b`.
* For release artifacts, use the version on the download page. For example, if you downloaded from <https://github.com/lf-edge/eve/releases/download/8.10.0/amd64.rootfs.img>, use `8.10.0`.

If you have an image for which you do not have the hash or semver version, you should be able to retrieve the version from the image itself.

* For Docker images, run the `version` command.. For example:

```sh
    $ docker run --rm lfedge/eve:0.0.0-master-0c6de671-kvm version
    0.0.0-master-0c6de671-kvm-arm64
```

* For release artifacts, mount or expand the `rootfs.img`, which is in squashfs format, and retrieve `/etc/eve-release`. For example:

```sh
    $ cat /tmp/unmounted/etc/eve-release
    8.10.0-kvm-amd64
```

With the specific release tag or commit in hand, go to this source repository <https://github.com/lf-edge/eve>, either on the Web or cloned locally.
Then check out the specific commit or tag. For example:

```sh
    $ git checkout 8.10.0
    $ # OR
    $ git checkout 0c6de671
```

At this point, you have the specific version of source code used to build the EVE binary distribution you are using.

## Binary to Builder Configuration

The specific configuration used to build this distribution of EVE is distributed inside the EVE OS image.
The actual configuration is available in binary `rootfs.img`, specifically in `/etc/linuxkit-eve-config.yaml`,
and thus is available on every running eve-os device.

It also is in the `lfedge/eve` container image, so you can run:

```sh
$ docker run --rm lfedge/eve:<version>-<hv> build_config
# e.g.
$ docker run --rm lfedge/eve:8.11.0-kvm build_config
```

A sample configuration is:

```yml
kernel:
  image: lfedge/eve-kernel:27897827d2e6fab1e2eb4f6ce0ea3a6d44a27cc1-amd64
  cmdline: "rootdelay=3"
init:
  - linuxkit/init:8f1e6a0747acbbb4d7e24dc98f97faa8d1c6cec7
  - linuxkit/runc:f01b88c7033180d50ae43562d72707c6881904e4
  - linuxkit/containerd:de1b18eed76a266baa3092e5c154c84f595e56da
  - linuxkit/getty:v0.5
  - linuxkit/memlogd:v0.5
  - lfedge/eve-dom0-ztools:417d4ff6a57d2317c9e65166274b0ea6f6da16e2-amd64
  - lfedge/eve-grub:080a301fbd8f1f1ef99013f81cc3c5aa2effface-amd64
  - lfedge/eve-fw:972657ee489ceb3efe7db7eb5907f9d3aeeaa1fd-amd64
  - lfedge/eve-gpt-tools:ab2e9f924e22709b4e08ebedd6d3c6a2882d071e-amd64
  - lfedge/eve-xen-tools:8c2a3e9d0f1b4a7c6e5d2f1a0b9c8d7e6f5a4b3c-amd64
onboot:
   - name: rngd
     image: lfedge/eve-rngd:ee02bc3f3273db42d7d05da21f02e1563072ad10-amd64
     command: ["/sbin/rngd", "-1"]
   - name: sysctl
     image: linuxkit/sysctl:v0.5
     binds:
        - /etc/sysctl.d:/etc/sysctl.d
     capabilities:
        - CAP_SYS_ADMIN
        - CAP_NET_ADMIN
   - name: modprobe
     image: linuxkit/modprobe:v0.5
     command: ["/bin/sh", "-c", "modprobe -a nct6775 w83627hf_wdt hpwdt wlcore_sdio wl18xx br_netfilter dwc3 rk808 rk808-regulator smsc75xx cp210x nicvf tpm_tis_spi rtc_rx8010 gpio_pca953x leds_siemens_ipc127 upboard-fpga pinctrl-upboard leds-upboard xhci_tegra 2>/dev/null || :"]
   - name: storage-init
     image: lfedge/eve-storage-init:82b0220db7a5cb1e56e127593b5d763ec0beb78d-amd64
services:
   - name: newlogd
     image: lfedge/eve-newlog:571319e0e6c6c8a21afd081409fafb3193fc7d3b-amd64
     cgroupsPath: /eve/services/newlogd
     oomScoreAdj: -999
   - name: edgeview
     image: lfedge/eve-edgeview:1f6fa3372dc20bcbabe357ee06550c2aae938063-amd64
     cgroupsPath: /eve/services/eve-edgeview
     oomScoreAdj: -800
   - name: debug
     image: lfedge/eve-debug:db1af614916c9bfb1d6144ae7e5b88acdbf58579-amd64
     cgroupsPath: /eve/services/debug
     oomScoreAdj: -999
   - name: wwan
     image: lfedge/eve-wwan:d714ad6c7facffa1c2a6ae13b9e76d55b10cd1a4-amd64
     cgroupsPath: /eve/services/wwan
     oomScoreAdj: -999
   - name: guacd
     image: lfedge/eve-guacd:98688a5b3c8972665225de789160c2bbdbdb4fd4-amd64
     cgroupsPath: /eve/services/guacd
     oomScoreAdj: -999
   - name: pillar
     image: lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64
     cgroupsPath: /eve/services/pillar
     oomScoreAdj: -999
   - name: vtpm
     image: lfedge/eve-vtpm:0d4173a868a9c23974e6e1b37e6369df5d4e272e-amd64
     cgroupsPath: /eve/services/vtpm
     oomScoreAdj: -999
   - name: watchdog
     image: lfedge/eve-watchdog:d4bf7ed4e3fa170061b8e6af6bd09ef7546c9c60-amd64
     cgroupsPath: /eve/services/watchdog
     oomScoreAdj: -1000
   - name: qemu
     image: lfedge/eve-qemu:1335e0e2d14d82ce3030f8d235f916474ae33bf4-amd64
     cgroupsPath: /eve/services/qemu
     oomScoreAdj: -999
files:
   - path: /etc/eve-release
     contents: '0.0.0-master-12a6fb8d-kvm-amd64'
   - path: /etc/linuxkit-eve-config.yml
     metadata: yaml
```

The above shows each container image used in creating this EVE bootable OS image. For example, the version of pillar used is
`lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64`.

The source for the builder configuration is rendered at build time from a series of templates.
The base templates are in [images/](../images/). Specifically, the primary configuration file is the template
[rootfs.yml.in](../images/rootfs.yml.in), which is rendered using templating, and potentially patched using
other files in the same directory.

As described above, when building an EVE image, the build process takes the final rendered configuration
actually used and save it in the EVE image at `/etc/linuxkit-eve-config.yml`.

## Container Images to Sources

With the specific name and tag of each OCI image in hand, you can trace the source for each such package.

The OCI container image can be pulled from Docker Hub using `docker pull`, for example:

```sh
    docker pull lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64
```

and it can be inspected using any image inspection tool, including `docker image inspect`:

```sh
    docker image inspect lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64
```

The results of the inspection will yield information about the container image, including tags that tell which git commit
was used when building this image. In the above example:

```json
      "Labels": {
        "org.mobyproject.config": "{\"capabilities\":[\"all\"],\"binds\":[\"/lib/modules:/lib/modules\",\"/dev:/dev\",\"/etc/resolv.conf:/etc/resolv.conf\",\"/r
un:/run\",\"/config:/config\",\"/:/hostfs\",\"/persist:/persist:rshared,rbind\",\"/usr/bin/containerd:/usr/bin/containerd\"],\"devices\":[{\"path\":\"all\",\"ty
pe\":\"a\",\"major\":0,\"minor\":0}],\"net\":\"host\",\"pid\":\"host\",\"rootfsPropagation\":\"shared\"}",
        "org.mobyproject.linuxkit.revision": "unknown",
        "org.mobyproject.linuxkit.version": "unknown",
        "org.opencontainers.image.revision": "12a6fb8d29a6b47f998cd077dfb92213f0e6a55f",
        "org.opencontainers.image.source": "https://github.com/linuxkit/linuxkit"
      },
```

The git commit for the above source is given in the label `"org.opencontainers.image.revision": "12a6fb8d29a6b47f998cd077dfb92213f0e6a55f"`, i.e.
you can get the same commit via `git checkout 12a6fb8d29a6b47f998cd077dfb92213f0e6a55f`.

The above _should_ be the same as the git commit you checked out in the stage [Binary to source commit](#binary-to-source-commit).
Nonetheless, even if it is not, the git commit given by the label is the git commit that was used to build
this particular container image.

Further, you can validate that the current contents of `pkg/pillar` give the correct output, by running:

```sh
$ linuxkit pkg show-tag pkg/pillar
lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b
```

The above `17837a9fcd05c765e9a1f6707b2e48f0f1dd215b` is the same git tree hash used in the container image tag,
`lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64`.

## Container sources to Content

With the specific source directory and commit in hand for each container image, we turn to the various sources that are used.

There are several types of content that are loaded used to create the container image.

### Local content

Local content includes anything in the same directory, which therefore is used in the
[docker build context](https://docs.docker.com/engine/reference/commandline/build/) when creating the container image.

Everything used in the source directory is committed to git. This includes sources, the `Dockerfile` itself, and the `build.yaml`
file used to control the image build via `linuxkit pkg build`.

Further, our build command, `linuxkit pkg build`, validates that the git repository is "clean", i.e. that there are no uncommitted changes
or files not saved in git. If there are, it treats the repository as "dirty", and appends both `dirty` and a hash of all of the file
contents in the directory to the tag. Thus `lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64` means that there were no
uncommitted changes or files in the source directory. If there were, it would have indicated on the tag as
`lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-dirty-<hash_of_file_contents>-amd64`.

Note that if the contents are "dirty", there is no guaranteed way to get to the original source. While the tag, and `linuxkit pkg show-tag`,
will include the git commit, the word `dirty`, and the hash of all of the file contents, there is no way to get to that specific set of
contents when it is dirty. The hash of the contents only tells you if it was the same, but does not provide a way to get there.

### Go modules

Most of the code unique to EVE is written in [go](http://golang.org). For all go package dependencies, all sources
use the [go module system](https://go.dev/ref/mod). It is beyond the scope of this document to describe the complete details of go's module
system and reproducibility. For more details, see the reference. This section provides a brief overview.

The list of each module used is available in `go.mod`, including the [semantic version (semver)](https://semver.org) if the module
uses semver, a hash otherwise. For example, [pkg/pillar/go.mod](../pkg/pillar/go.mod) contains partially:

```go
require (
    cloud.google.com/go/storage v1.21.0 // indirect
    github.com/Focinfi/go-dns-resolver v1.0.1
    github.com/anatol/smart.go v0.0.0-20220615232124-371056cd18c3
```

Some of the above include only semver, and some include the precise git commit and date.

To get the source of each of those:

1. Retrieve the URL to the source
1. Retrieve the semver tag or commit
1. Check out the tag or commit

We will look at examples from the above `go.mod`.

#### semver

The first required module is:

```go
    cloud.google.com/go/storage v1.21.0 // indirect
```

The source is at `cloud.google.com/go/storage`. You can get the exact code used by cloning the repository and checking out the
tag `v1.21.0` or referencing it online.

Of course, git tags are mutable and can change. To avoid issues, the go module system includes a cryptographic hash
of the contents either of the module itself or the module's own `go.mod` file in `go.sum`. The relevant section
from [pkg/pillar/go.sum](../pkg/pillar/go.sum) is:

```go
cloud.google.com/go/storage v1.21.0 h1:HwnT2u2D309SFDHQII6m18HlrCi3jAXhUMTLOWXYH14=
cloud.google.com/go/storage v1.21.0/go.mod h1:XmRlxkgPjlBONznT2dDUU/5XlpU2OjMnKuqnZI01LAA=
```

The cryptographic hash of the zip file for the contents is `HwnT2u2D309SFDHQII6m18HlrCi3jAXhUMTLOWXYH14=`, while the
hash of the `go.mod` file is `XmRlxkgPjlBONznT2dDUU/5XlpU2OjMnKuqnZI01LAA=`. The above is base64-encoded sha256 sum, as indicated
by `h1`. For further details, see the [go modules reference](https://go.dev/ref/mod).

#### commit

The third module is:

```go
    github.com/anatol/smart.go v0.0.0-20220615232124-371056cd18c3
```

The source is at `github.com/anatol/smart.go`. You can get the exact code used by cloning the repository and checkout out the commit
`371056cd18c3` or referencing it online. Note that it also includes the date and time of the commit.

As for semver, go modules preserves the cryptographic hash of the contents of the module, even when a commit is used.

The relevant section from [pkg/pillar/go.sum](../pkg/pillar/go.sum) is:

```go
github.com/anatol/smart.go v0.0.0-20220615232124-371056cd18c3 h1:0nVT/S4r4gSyJNb/74vZaTjW7izLUZ/CRtcuH+G2DcE=
github.com/anatol/smart.go v0.0.0-20220615232124-371056cd18c3/go.mod h1:F486dIGdTbYMmAj8dtlVbjQasL8WS7lhnijBk4wJmKQ=
```

The cryptographic hash of the zip file for the contents is `0nVT/S4r4gSyJNb/74vZaTjW7izLUZ/CRtcuH+G2DcE=`, while the
hash of the `go.mod` file is `F486dIGdTbYMmAj8dtlVbjQasL8WS7lhnijBk4wJmKQ=`. The above is base64-encoded sha256 sum, as indicated
by `h1`. For further details, see the [go modules reference](https://go.dev/ref/mod).

There is an example of a script which determines the go pkgref from the content of the go.sum files and downloads the source code in [tools/go-sum-to-src.sh](../tools/go-sum-to-src.sh). See comment in the script for its usage.

### External sources

Some of the container image sources may require external software from the Internet. For example, [pkg/fw](../pkg/fw) needs to
download various firmware packages.

Container image sources in [pkg/](../pkg/) are not discouraged from downloading such software. However, they are required to
use specific versions, preferably immutable, and, wherever possible, commit based. When possible, they also are encouraged to store
the hash of contents locally to validate that it has not changed.

The precise commit gives the ability to retrieve the precise source used.

Continuing the [pkg/fw](../pkg/fw) example, part of the [pkg/fw/Dockerfile](../pkg/fw/Dockerfile) contains:

```dockerfile
ENV RPI_FIRMWARE_VERSION 2c8f665254899a52260788dd902083bb57a99738
ENV RPI_FIRMWARE_URL https://github.com/RPi-Distro/firmware-nonfree/archive
RUN mkdir /rpi-firmware &&\
    curl -fsSL ${RPI_FIRMWARE_URL}/${RPI_FIRMWARE_VERSION}.tar.gz | tar -xz --strip-components=1 -C /rpi-firmware &&\
    cp -a /rpi-firmware/debian/config/brcm80211/brcm/brcmfmac43436* /lib/firmware/brcm
```

By inspecting the Dockerfile, we can see the source of the Raspberry Pi firmware used and the precise commit.

### Ubuntu packages

The source for standard packages, such as `gcc` for compilation or `openssl` or `bash` for useful utilities, is the operating
system package manager. In the case of all of the container images, the base image, shown as `FROM` in the Dockerfile,
is [Ubuntu](https://ubuntu.com), in the form of EVE's own base image [lfedge/eve-ubuntu](https://hub.docker.com/r/lfedge/eve-ubuntu),
whose source is at [pkg/ubuntu](../pkg/ubuntu). All container images included in EVE OS **must** use that image as the base.

Ubuntu's archive moves: `apt-get install <packagename>` gives whatever version the `-updates` and `-security` pockets carry
that day. `lfedge/eve-ubuntu` therefore resolves every package against one timestamp of the
[Ubuntu snapshot service](https://snapshot.ubuntu.com), `UBUNTU_SNAPSHOT` in [pkg/ubuntu/Dockerfile](../pkg/ubuntu/Dockerfile),
and mirrors the resulting `.deb` files inside the image. The snapshot service keeps every version it served, so the exact
binary package, and from it the exact source package, can always be retrieved again.

The base image includes a utility called `eve-ubuntu-deploy.sh`, which simplifies installation of packages based
on environment variables.

For example, [pkg/mkconf/Dockerfile](../pkg/mkconf/Dockerfile) starts with:

```dockerfile
FROM lfedge/eve-ubuntu:9a6ebfad80ca4d18950553f8bf2c01a068869805 AS build
ENV PKGS="mtools dosfstools"
RUN eve-ubuntu-deploy.sh
```

The above means:

1. Use the base image `lfedge/eve-ubuntu:9a6ebfad80ca4d18950553f8bf2c01a068869805`
1. Use `eve-ubuntu-deploy.sh` to install all of the packages listed in `PKGS` from the mirror in the base image: `mtools dosfstools`

Using the above, we can trace the packages and sources for a particular container image, assuming we already have the source
repository and git commit, from the previous steps. The steps below will be followed by an example.

1. Locate the `Dockerfile` in the source for the container image.
1. From the `Dockerfile`, find the `lfedge/eve-ubuntu` base image used.
1. From the container image itself, retrieve the dpkg status database at `/var/lib/dpkg/status`, and the records of
   packages built from source at `/var/lib/dpkg/status.d/*`.
1. From the records, retrieve the source package name and version, and from the snapshot the source package itself.

We will walk through a practical example with the `lfedge/eve-mkconf` image.

We now need to retrieve the list of all packages and versions installed. It is **not** sufficient to just look at the list
in the `Dockerfile`, as one package may have upstream dependencies that get installed automatically. Instead, we need to look at the actual
image itself, and specifically dpkg's status file at `/var/lib/dpkg/status`.

You can use any tool you like to copy files from a container image. We use a simple `docker create` then
`docker cp` then `docker rm`.

```sh
    $ docker create lfedge/eve-mkconf:a455da5203e484bbcc3212e0dae8536287a8ff1c-amd64
    364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7
    $ docker cp 364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7:/var/lib/dpkg/status /tmp/status
    $ docker rm 364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7
    364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7
```

The `status` file's structure is described in [deb-control(5)](https://manpages.ubuntu.com/manpages/noble/man5/deb-control.5.html) and
[dpkg(1)](https://manpages.ubuntu.com/manpages/noble/man1/dpkg.1.html).

The key parts are that each package is given in a paragraph, with blank lines separating packages. For example:

```text
Package: mtools
Status: install ok installed
Priority: optional
Section: otherosfs
Installed-Size: 388
Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>
Architecture: amd64
Version: 4.0.48-1
Depends: libc6 (>= 2.38)
Description: Tools for manipulating MSDOS files
Homepage: https://www.gnu.org/software/mtools/
```

The most important parts for our purposes are:

* The name: `Package: mtools`
* The version: `Version: 4.0.48-1`
* The source package, if its name differs from the binary package: `Source: glibc` (for `libc6`), optionally with a version in parentheses when it differs

The binary packages of one source package, e.g. `libc6`, `libc6-dev` and `libc-bin` from `glibc`, share the source. To get it,
look the source package up in the `Sources` index of the same snapshot the base image was built from: the timestamp is in
`pkg/ubuntu/Dockerfile`, and every container carries it in `/etc/apt/sources.list.upstream`. The index at

```sh
https://snapshot.ubuntu.com/ubuntu/${TIMESTAMP}/dists/${POCKET}/${COMPONENT}/source/Sources.gz
```

names, for each source package and version, the `.dsc` file, the upstream tarball and the Debian/Ubuntu packaging tarball
in the `pool/` of the archive, with their checksums. For `mtools 4.0.48-1` these are `mtools_4.0.48-1.dsc`,
`mtools_4.0.48.orig.tar.bz2` and `mtools_4.0.48-1.debian.tar.xz` below `pool/main/m/mtools/`. The `.dsc` lists the
upstream `Homepage` and the packaging tarball contains the patches Ubuntu applied, `debian/patches/series` being their order.

Packages built from source by a Dockerfile rather than installed from Ubuntu, such as `kexec-tools` in
[pkg/kexec](../pkg/kexec/Dockerfile), are recorded by `register-sbom-pkg.sh` as one file per package below
`/var/lib/dpkg/status.d/`, with the upstream URL as `Homepage` and the version the Dockerfile fetched; the Dockerfile's
`ADD` line is the source reference for those.

There is a script which follows the above description to download the source packages for every Ubuntu package found in an
EVE image in [tools/get-deb-pkg-source.sh](../tools/get-deb-pkg-source.sh). It is used by
[tools/collect-sources.sh](../tools/collect-sources.sh) to collect the sources of a release, see [SBOM-AND-SOURCES.md](SBOM-AND-SOURCES.md).

**Note:** The kernel is no longer built from source under `pkg/kernel/`. It is now maintained in a separate repository ([lf-edge/eve-kernel](https://github.com/lf-edge/eve-kernel)) and consumed by EVE as a pre-built container image. See [KERNEL.md](KERNEL.md) for current kernel build documentation.

The kernel generates SBOM (Software Bill of Materials) internally as part of the build process, and the SBOM is included in the kernel container image. The kernel source code can be traced through the eve-kernel repository. There is a script to collect the source code used for the kernel build (and in general, extract source code from Docker ADD commands). See comments in [tools/get-kernel-source.sh](../tools/get-kernel-source.sh) for the usage.
