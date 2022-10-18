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
   * Alpine packages

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
$ docker run --rm lfedge/eve:<version> build_config
# e.g.
$ docker run --rm lfedge/eve:8.11.0 build_config
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
  - lfedge/eve-xen:9bf0be924fc91c74b993d7cf3ed5f4523fb09cee-amd64
  - lfedge/eve-gpt-tools:ab2e9f924e22709b4e08ebedd6d3c6a2882d071e-amd64
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
   - name: wlan
     image: lfedge/eve-wlan:f60f85ed52a9731dc8714b058d2dec71dab97cfd-amd64
     cgroupsPath: /eve/services/wlan
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
   - name: xen-tools
     image: lfedge/eve-xen-tools:1335e0e2d14d82ce3030f8d235f916474ae33bf4-amd64
     cgroupsPath: /eve/services/xen-tools
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

The above _should_ be the same as the git commit you checked out in the stage [Binary to source commit][Binary to source commit].
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

### Alpine packages

The source for standard packages, such as `go` or `gcc` for compilation or `openssl` or `bash` for useful utilities, is the operating
system package manager. In the case of all or almost all of the container images, the base image, shown as `FROM` in the Dockerfile,
that is [Alpine Linux](https://www.alpinelinux.org).

Alpine Linux uses the [apk package manager](https://wiki.alpinelinux.org/wiki/Package_management). Unfortunately, apk changes
package versions for the default install via `apk add <packagename>`, and even when pinned to a specific version, it can change the
underlying bits for a particular version. This can make it challenging to track precisely which version of a apckage was used and,
therefore, which software.

For example, [pkg/pillar](../pkgs/pillar) requires the following Alpine packages to be installed via apk:
`alpine-baselayout musl-utils bash glib squashfs-tools util-linux e2fsprogs e2fsprogs-extra keyutils dosfstools coreutils sgdisk smartmontools`.

Given that `apk add alpine-baselayout` or `apk add glib` can be any version, EVE provides a methdology for tracking the precise package and, by
extension, source used when installing those packages.

All container images used in the EVE OS image do **not** source from [the standard Alpine container image](https://hub.docker.com/_/alpine).
Instead, EVE itself creates an Alpine package cache called [lfedge/eve-alpine](https://hub.docker.com/r/lfedge/eve-alpine), whose source is
at [pkg/alpine](../pkg/alpine). All container images included in EVE OS **must** use that cache as the base.

The Alpine cache image often is referred to as the Alpine "base" image.

Further, the cache container image includes a utility called `eve-alpine-deploy.sh`, which simplifies installation of apk packages based
on environment variables.

For example, [pkg/pillar/Dockerfile](../pkg/pillar/Dockerfile) starts with:

```dockerfile
FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as build
ENV PKGS alpine-baselayout musl-utils bash glib squashfs-tools util-linux e2fsprogs e2fsprogs-extra keyutils dosfstools coreutils sgdisk smartmontools
RUN eve-alpine-deploy.sh
```

The above means:

1. Use the cache, or base, image `lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52`
1. Use `eve-alpine-deploy.sh` to install all of the packages listed in `PKGS` from the cache image: `alpine-baselayout musl-utils bash glib squashfs-tools util-linux e2fsprogs e2fsprogs-extra keyutils dosfstools coreutils sgdisk smartmontools`

The images in the cache are stored in `.apk` format.

Using the above, we can trace the apk packages and sources for a particular container image, assuming we already have the source
repository and git commit, from the previous steps. The steps below will be followed by an example.

1. Locate the `Dockerfile` in the source for the container image.
1. From the `Dockerfile`, find the `lfedge/eve-alpine` cache image used.
1. From the container image itself, retrieve the Alpine apk installed database at `/lib/apk/db/installed`
1. From the `installed` file, retrieve the specific URL to the source and version or commit used to build the package.

We will walk through a practical example, continuing to use our `lfedge/eve-pillar` image from above.

From the `Dockerfile`, we retrieved the cache image of `lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52`.

We now need to retrieve the list of all packages and versions installed. If it **not** sufficient to just look at the list
in the `Dockerfile`, as one package may have upstream dependencies that get installed automatically. Instead, we need to look at the actual
image itself, and specifically Alpine's installed list at `/lib/apk/db/installed`.

You can use any tool you like to copy files from a container image. We use a simple `docker create` then
`docker cp` then `docker rm`.

```sh
    $ docker create lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64
    364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7
    $ docker cp 364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7:/lib/apk/db/installed /tmp/installed
    $ docker rm 364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7
    364cdf9537a77bff25379c557da7d63f4993ecd4baf9b567e745bfe855e937e7
```

The `installed` file's structure is described at [the official page](https://wiki.alpinelinux.org/wiki/Apk_spec#Index_Format_V2).

The key parts are that each package is given in a paragraph, with blank lines separating packages. For example:

```text
C:Q1aCu0LmUDoAFSOX49uHvkYC1WasQ=
P:musl
V:1.2.3-r0
A:x86_64
S:383304
I:622592
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT
o:musl
m:Timo Teräs <timo.teras@iki.fi>
t:1649396308
c:ee13d43a53938d8a04ba787b9423f3270a3c14a7
p:so:libc.musl-x86_64.so.1=1
F:lib
R:ld-musl-x86_64.so.1
a:0:0:755
Z:Q1ZZqflKEvStJz4SXV0SDMi3wOtM0=
R:libc.musl-x86_64.so.1
a:0:0:777
Z:Q17yJ3JFNypA4mxhJJr0ou6CzsJVI=

C:Q1iZ+C2JJdBlm2KKtAOkSkM7zZegY=
P:busybox
V:1.35.0-r17
A:x86_64
S:507831
I:962560
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
o:busybox
m:Sören Tempel <soeren+alpine@soeren-tempel.net>
t:1659366884
c:2bf6ec48e526113f87216683cd341a78af5f0b3f
D:so:libc.musl-x86_64.so.1
p:/bin/sh cmd:busybox=1.35.0-r17 cmd:sh=1.35.0-r17
r:busybox-initscripts
F:bin
R:busybox
a:0:0:755
Z:Q1WUwBY0eOGgzgVxTZxJBZPyQUicI=
R:sh
a:0:0:777
Z:Q1pcfTfDNEbNKQc2s1tia7da05M8Q=
F:etc
R:securetty
Z:Q1mB95Hq2NUTZ599RDiSsj9w5FrOU=
R:udhcpd.conf
Z:Q1EgLFjj67ou3eMqp4m3r2ZjnQ7QU=
F:etc/logrotate.d
R:acpid
Z:Q1TylyCINVmnS+A/Tead4vZhE7Bks=
F:etc/network
F:etc/network/if-down.d
F:etc/network/if-post-down.d
F:etc/network/if-post-up.d
F:etc/network/if-pre-down.d
F:etc/network/if-pre-up.d
F:etc/network/if-up.d
R:dad
a:0:0:775
Z:Q1ORf+lPRKuYgdkBBcKoevR1t60Q4=
F:sbin
F:tmp
M:0:0:1777
F:usr
F:usr/sbin
F:usr/share
F:usr/share/udhcpc
R:default.script
a:0:0:755
Z:Q1t9vir/ZrX3nbSIYT9BDLWZenkVQ=
F:var
F:var/cache
F:var/cache/misc
F:var/lib
F:var/lib/udhcpd

...

C:Q1JdllpChcMaHc7DnVs+DRWAnD2zE=
P:ip6tables
V:1.8.8-r1
A:x86_64
S:41963
I:348160
T:Linux kernel firewall, NAT and packet mangling tools
U:https://www.netfilter.org/projects/iptables/index.html
L:GPL-2.0-or-later
o:iptables
m:Natanael Copa <ncopa@alpinelinux.org>
t:1652905555
c:e7e60a9e6ff8cc55b004dac6392b75e4993518da
D:iptables=1.8.8-r1 so:libc.musl-x86_64.so.1 so:libxtables.so.12
r:ebtables
F:sbin
R:ip6tables
a:0:0:777
Z:Q12mo8ikesb2KnfgWolLj1gsf4cwc=
R:ip6tables-apply
a:0:0:777
Z:Q1D7sdEIH4PzvxaB7e3X8EmxgVsu4=
R:ip6tables-legacy
a:0:0:777
Z:Q12mo8ikesb2KnfgWolLj1gsf4cwc=
R:ip6tables-legacy-restore
a:0:0:777
Z:Q12mo8ikesb2KnfgWolLj1gsf4cwc=
R:ip6tables-legacy-save
a:0:0:777
Z:Q12mo8ikesb2KnfgWolLj1gsf4cwc=
R:ip6tables-nft
a:0:0:777
Z:Q1WPPdXUGL+Fma+jYAArGGbVCwOqk=
R:ip6tables-nft-restore
a:0:0:777
Z:Q1WPPdXUGL+Fma+jYAArGGbVCwOqk=
R:ip6tables-nft-save
a:0:0:777
Z:Q1WPPdXUGL+Fma+jYAArGGbVCwOqk=
R:ip6tables-restore
a:0:0:777
Z:Q12mo8ikesb2KnfgWolLj1gsf4cwc=
R:ip6tables-restore-translate
a:0:0:777
Z:Q1WPPdXUGL+Fma+jYAArGGbVCwOqk=
R:ip6tables-save
a:0:0:777
Z:Q12mo8ikesb2KnfgWolLj1gsf4cwc=
R:ip6tables-translate
a:0:0:777
Z:Q1WPPdXUGL+Fma+jYAArGGbVCwOqk=
F:usr
F:usr/lib
F:usr/lib/xtables
R:libip6t_DNPT.so
a:0:0:755
Z:Q1WraOfsi+kgSlIN7aQ+Rq35GP1S4=
R:libip6t_HL.so
a:0:0:755
Z:Q1lZ7H8yyq0Vu0wFW80bpvoP2gnug=
R:libip6t_LOG.so
a:0:0:755
Z:Q1jPvkFPJ9Wlmu6G44oaB4odBdqf0=
R:libip6t_MASQUERADE.so
a:0:0:755
Z:Q11PFah9jKg2t3CrG2+YK9NshCE6o=
R:libip6t_NETMAP.so
a:0:0:755
Z:Q13g7xSrZBAfa3Nr78FdkHF+pFctM=
R:libip6t_REJECT.so
a:0:0:755
Z:Q1vM7gC27Uv7lEoDXI+EIDqvqXpss=
R:libip6t_SNAT.so
a:0:0:755
Z:Q1j/XbdyaCkMPOJbyGZqprs7HXdas=
R:libip6t_SNPT.so
a:0:0:755
Z:Q1WB5IwC5Q9mr5okiSdLgw4ezo7u4=
R:libip6t_ah.so
a:0:0:755
Z:Q1hFgkHm/vd4Fjc+LQ8Uoe6bPIt7o=
R:libip6t_dst.so
a:0:0:755
Z:Q1drVG6nuYR9TJZWhaUHtKHyg6tkc=
R:libip6t_eui64.so
a:0:0:755
Z:Q1vleF/Hbue2DhlyoKJ4wJtDHgJjo=
R:libip6t_frag.so
a:0:0:755
Z:Q1ejt6B8/0AwnyX9N0LBh8q//f+kU=
R:libip6t_hbh.so
a:0:0:755
Z:Q16IsIQy+q7V5qdxt710Mqds6M0e8=
R:libip6t_hl.so
a:0:0:755
Z:Q1udmHKTC6alJKFzVBdbSJz23ATZY=
R:libip6t_icmp6.so
a:0:0:755
Z:Q1QGhlbChLsiMHYHrji3SLp62wRQQ=
R:libip6t_ipv6header.so
a:0:0:755
Z:Q1XI/vQ7njuNFN8aNA0LKTSgCaxXg=
R:libip6t_mh.so
a:0:0:755
Z:Q1hESH+jdme+AnTNPQ4c5HIXS8qCY=
R:libip6t_rt.so
a:0:0:755
Z:Q1vLoeZs41MWkOdJX9ceGnmN7MYyA=
R:libip6t_srh.so
a:0:0:755
Z:Q1ry15xfrU3eLcYzqoMj32ZTRTaY8=
F:var
F:var/lib
F:var/lib/ip6tables
```

The package listing provides information about every file installed: the name of the package, the origin of the package if it is
an alias, the source commit used to build the package, and every file installed with its permissions.

Using the `ip6tables` install above as an example, it contains a lot of information. the most important parts for our purposes are:

* The name: `P:ip6tables`
* The origin, i.e. the original package: `o:iptables`
* The version: `V:1.8.8-r1`
* The commit: `c:e7e60a9e6ff8cc55b004dac6392b75e4993518da`

If `o` for origin exists, then that is the name of the package as stored in the Alpine package source; the package name `P` is just an alias.

The commit `c` is not the commit of the original source, but the commit in the Alpine packages git repository that built the package.
To get the full source, we go to the Alpine Linux git URL that includes the package name and hash:

```sh
https://git.alpinelinux.org/aports/tree/main/${PACKAGENAME}/APKBUILD?id=${COMMIT}
```

For our example, that is:

```sh
https://git.alpinelinux.org/aports/tree/main/iptables/APKBUILD?id=e7e60a9e6ff8cc55b004dac6392b75e4993518da
```

The file there shows:

```sh
# Maintainer: Natanael Copa <ncopa@alpinelinux.org>
pkgname=iptables
pkgver=1.8.8
pkgrel=1
pkgdesc="Linux kernel firewall, NAT and packet mangling tools"
url="https://www.netfilter.org/projects/iptables/index.html"
arch="all"
license="GPL-2.0-or-later"
depends_dev="linux-headers"
makedepends="$depends_dev libnftnl-dev bison flex autoconf automake"
subpackages="ip6tables $pkgname-doc $pkgname-dev $pkgname-openrc ip6tables-openrc:ip6tables_openrc"
provides="ebtables" # for backards compat
replaces="ebtables"
source="https://www.netfilter.org/projects/iptables/files/iptables-$pkgver.tar.bz2
    use-sh-iptables-apply.patch
    iptables.initd
    iptables.confd
    ip6tables.confd
    ebtables.initd
    ebtables.confd

    fix-xtables.patch
    fix-u_int16_t.patch
    "

build() {
    export CFLAGS="$CFLAGS -D_GNU_SOURCE"
    ./configure \
        --build="$CBUILD" \
        --host="$CHOST" \
        --prefix=/usr \
        --mandir=/usr/share/man \
        --sbindir=/sbin \
        --sysconfdir=/etc \
        --without-kernel \
        --enable-devel \
        --enable-libipq \
        --enable-shared

    # do not use rpath
    sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
    sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool

    make
}

package() {
    make -j1 install DESTDIR="$pkgdir"

    mkdir -p "$pkgdir"/usr/include/libiptc \
        "$pkgdir"/usr/lib \
        "$pkgdir"/var/lib/iptables \
        "$pkgdir"/etc/iptables

    install -m644 include/iptables.h include/ip6tables.h \
        "$pkgdir"/usr/include/
    install include/libiptc/*.h "$pkgdir"/usr/include/libiptc/

    install -D -m755 "$srcdir"/iptables.initd "$pkgdir"/etc/init.d/iptables
    install -D -m644 "$srcdir"/iptables.confd "$pkgdir"/etc/conf.d/iptables
    install -D -m755 "$srcdir"/ebtables.initd "$pkgdir"/etc/init.d/ebtables
    install -D -m644 "$srcdir"/ebtables.confd "$pkgdir"/etc/conf.d/ebtables
}

ip6tables() {
    mkdir -p "$subpkgdir"
    cd "$subpkgdir"

    mkdir -p sbin \
        var/lib/ip6tables \
        usr/lib/xtables

    mv "$pkgdir"/sbin/ip6* sbin/
    mv "$pkgdir"/usr/lib/xtables/libip6* usr/lib/xtables/
}

ip6tables_openrc() {
    default_openrc

    install -D -m755 "$srcdir"/iptables.initd "$subpkgdir"/etc/init.d/ip6tables
    install -D -m644 "$srcdir"/ip6tables.confd "$subpkgdir"/etc/conf.d/ip6tables
}

sha512sums="
f21df23279a77531a23f3fcb1b8f0f8ec0c726bda236dd0e33af74b06753baff6ce3f26fb9fcceb6fada560656ba901e68fc6452eb840ac1b206bc4654950f59  iptables-1.8.8.tar.bz2
ac78898c2acbe66ed8d32a06f41ff08cde7c22c3df6dfec6bc89a912d2cef2bde730de19d25a5407886d567cb0972a0b7bde7e6b18a34c4511495b4dad3b90ad  use-sh-iptables-apply.patch
a37c17a5382c756fcfb183af73af2283f0d09932c5a767241cbab5d784738f6f587f287a0cdf13b4fa74724ecd3a2063a9689ccee84c1bda02e730f63480f74d  iptables.initd
cb7fecd5cab2c78bd3f215a41f39ec11c37eb360efbe83982378a0e647e0aa9dc0b7ec915a5b5081aa2f7747464787e69404aa15ba15a063c32cb8fb7dd13d1e  iptables.confd
0897a7a22f8b700f7f1f5c355ad6cbf39740e44d6c962af99e479978d8a2d556ca7fe4e31f238829046b4a871ce0b5fd52e2544f1361d15dd1ea3e33992646c4  ip6tables.confd
8809d6fc69fbaa7d83ca4675d9e605f73e74ea8907495d39abdfbdca5c74bafb4fe0e413c88a4bd9470688a243581fa239527af06be15c9c94190664d9557fca  ebtables.initd
1623109d7b564b817904e35b6c6964ce84fe123a8ae1b656944648a39cfef719431cfad313b48eb36ae53a0d1a6b388a5caec1a990448d02f77e5d12b1f7ee9d  ebtables.confd
ce8c4ff001be49b77bb82efc3cb8b9f3c8f8684abcb07d079c6a00fab5c7a22e0d7f66f8ccdf3aab63d8fdb2b01b249679a89561e2f723111c8ce4075681b134  fix-xtables.patch
015ca550cf27802446d74521b7618095a342663d4fd73700975f3186428ecdc9eec27016f4d40862d3837cbbe0bb43509c1022b19ef8692ab28cc24e18831d57  fix-u_int16_t.patch
"
```

Describing how apk builds work and how to read the entire `APKBUILD` file is beyond the scope of this document. The important points
for our purposes are:

* The URL to the source code: `source="https://www.netfilter.org/projects/iptables/files/iptables-$pkgver.tar.bz2"`
* Any referenced versions or commits used in that URL: `pkgver=1.8.8`

The above is a reference to the original root source code for the binaries distributed.

There is an example of a script which follows the above description to download the APKBUILD files, and any patches, as well as any http and https references i.e., the complete source for the underlying package plus the alpine build recipe in [tools/get-alpine-pkg-source.sh](../tools/get-alpine-pkg-source.sh). See comment in the script for its usage.

The kernel is built from source using [pkg/kernel/Dockerfile](../pkg/kernel/Dockerfile). There is a script to collect the source code used for the kernel build (and in general, extract source code from Docker ADD commands). See comments in [tools/get-kernel-source.sh](../tools/get-kernel-source.sh) for the usage.
