# EVE Reproducibility

A key element of EVE is its consistency. Among other things, that means that it must be possible to rebuild EVE images, and the packages that are composed to form EVE, and get functionally identical bits.

We write "functionally identical" rather than "precisely identical" or just "identical", because the compilation and composition process can change
elements like timestamps or randomly generated data, leading to minor differences. Ideally, two builds of EVE from the same source would be
precisely identical; that is a future goal. However, functionally identical images are a requirement for EVE.

This document describes the reproducibility structures and process of EVE. It answers the "source-to-binary" question:

    given that I have a specific version of this source code repository, how does the process ensure that I will get an
    image that is functionally identical every time I run it, or else fail?

This means that EVE's build process should always lead to one of only two outcomes:

* Successfully build a functionally identical image; OR
* Fail to build.

It never should succeed in producing an image if it cannot produce one that is functionally identical. For example, if
a part of the process depends on downloading a specific version of a dependency, then it must either get that precise version,
or fail. It should not fall back to getting another version.

It answers the question at multiple levels, each a layer deeper than the previous:

1. EVE OS Images: how is the distributed, bootable EVE OS image created, and how does the build process render it reproducible.
1. Package Images: how are the OCI container images that are used in the EVE OS image created, and how does the build process render them reproducible.
1. OS Packages: how are the OS packages used inside the OCI container images consumed, and how does the build process render them reproducible.

It does **not** answer the question, "given an image, how do I trace the precise source that created it?" The answer
to that question, binary-to-source, is available in [EVE-IMAGE-SOURCES.md](./EVE-IMAGE-SOURCES.md).

The description of the build process in [BUILD.md](./BUILD.md) is helpful in understanding how the build works in detail.

## EVE OS Images

EVE OS images are composed using [linuxkit](https://github.com/linuxkit/linuxkit). Linuxkit uses OCI container image contents to compose the
bootable operating system.

The yaml-format configuration files for composing the operating system are in [../images], primarily [rootfs.yml.in](../images/rootfs.yml.in).
The detailed description of the yaml format can be found in [the linuxkit docs](https://github.com/linuxkit/linuxkit/blob/master/docs/yaml.md).

Each container image used as an input is provided with a precise and unchanging tag.

There are two image formats in the yaml file: fixed and templated.

### Fixed Images

Fixed tags are those that look like normal container images with tags or hashes. For example:

* `linuxkit/init:8f1e6a0747acbbb4d7e24dc98f97faa8d1c6cec7`
* `linuxkit/getty:v0.5`

While tags on OCI registries, like [Docker Hub](https://hub.docker.com), are mutable, EVE only uses tags that are never mutated. This is true for both tags on `lfedge/eve-*` images, and those that come from upstream or other sources, like `linuxkit/*`.

The semver tags, like `v0.5`, are never changed, nor are the hash-based tags.

The hash-tags are, in all cases, the hash of the git-commited source tree of the package. Using the above example, the source to the `linuxkit/init` image
is in this directory [https://github.com/linuxkit/linuxkit/tree/master/pkg/init](https://github.com/linuxkit/linuxkit/tree/master/pkg/init). When building the
container image, it is tagged with the git hashed content of the directory tree. Thus, the result of that hash at the time the image was built
was `8f1e6a0747acbbb4d7e24dc98f97faa8d1c6cec7`.

It is possible to lock them down further, and make mutating tags impossible to slip through, by adding image index hashes to the yaml file, e.g.:

* `linuxkit/init:8f1e6a0747acbbb4d7e24dc98f97faa8d1c6cec7@sha256:5c503aa479ae89ff7e3ea5e9d6c427e58ec78b7216ba1ad3cb2e4da2720913f0`
* `linuxkit/getty:v0.5@sha256:6eba389196328d02ad01aea691a60931a42b6c81978a33f87e770df902869b9c`

### Templated Images

The other image names are templated. These are all capitalized, and end in `_TAG`. For example:

* `RNGD_TAG`
* `PILLAR_TAG`

These are not consumable by linuxkit; instead, the `Makefile` target that builds an EVE image, `make eve`, calls lower-level targets that parse
this templated yaml file [rootfs.yml.in](../images/rootfs.yml.in), replacing all templates that end in `_TAG` with the appropriate image tags.

These tags are calculated from the relevant directory. For example, `RNGD_TAG` is calculated based on the image that would be generated
from the directory [pkg/rngd](../pkg/rngd/), and `PILLAR_TAG` based on the directory [pkg/pillar](../pkg/pillar/).

The actual image name and tag are calculated identically to the process for the fixed tags, i.e. the git hash of the directory tree.
The calculation is provided by running `linuxkit pkg show-tag dir/`. For example:

    ```sh
    $ linuxkit pkg show-tag pkg/pillar
    lfedge/eve-pillar:b20146debd08bbfffb23f53fc9f5c3c4af377f67
    ```

With the template complete, every OCI container image used to compose an EVE operating system is in the generated `rootfs.yml`, each of which
contains a hash of the state of the source at generation time.

## Package Images

The packages used as part of the EVE OS composition process are standard OCI container images.

As described above in [EVE OS Images](#eve-os-images), all of the packages used to compose a bootable EVE image
are configured in [rootfs.yml.in](../images/rootfs.yml.in). Those container images are from one of two sources:

* `docker.io/linuxkit/*` whose sources are [https://github.com/linuxkit/linuxkit/tree/master/pkg/](https://github.com/linuxkit/linuxkit/tree/master/pkg/)
* `docker.io/lfedge/eve-*` whose sources are in this repository under [../pkg](../pkg)

Every source directory is git committed. As described above, when the source is compiled into an OCI container image, it always is named as follows:

* the name of the image, e.g. `lfedge/eve-pillar`, is in the directory's `build.yaml` which, itself, is in git
* the tag of the image, e.g. `b20146debd08bbfffb23f53fc9f5c3c4af377f67`, is calculated based on the git hash of the directory tree

Further, if the directory is git "dirty", i.e. has any uncommitted files that are not in `.gitignore`, or has changed but uncommitted files,
then the image tag is appended with the word `dirty` and the hash of the contents of the directory, e.g.
`b20146debd08bbfffb23f53fc9f5c3c4af377f67-dirty-abcdefg112334`.

The sources to all components used in the image, based on the `Dockerfile`, must come from one of several places.

|Source|Method|Reproducibility|
|---|---|---|
|Another container image|Using `FROM` in the Dockerfile|Must use a properly immutably tagged image or one that includes the content hash|
|Internet|`curl`, `wget` or other download|Must download a specific version and, wherever possible, check the content hash, md5 or sha|
|Go packages|`go mod` or `go get`|Go inherently records the specific hash of the package version used in `go.sum`, which itself is git committed|
|OS packages|`eve-ubuntu-deploy.sh` (`apt-get install` from the base image mirror)|See next section|

It is possible for human error in any of the above to slip through. EVE uses peer review and maintainer approval to reduce the probabilities of
any non-reproducible source slipping in.

Further, the EVE project is exploring additional gates. These include:

* Contributors certifying on each Pull Request that they have not used non-reproducible sources.
* Regular automated audits of all `pkg/` sources.
* CI scans of `pkg/` sources.

## Linux Packages

The primary source for many software packages in Linux is the OS packaging system. All of the `lfedge/eve-*` OCI images used
in EVE are based on [Ubuntu](https://ubuntu.com), which uses the [apt package manager](https://ubuntu.com/server/docs/package-management)
and `.deb` packages; the `linuxkit/*` images EVE takes from upstream are based on [Alpine](https://hub.docker.com/_/alpine)
and its [apk package manager](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper).

For example, to install bash on Ubuntu:

    ```sh
    apt-get install bash
    ```

Distribution packages create unique challenges for reproducibility. Specifically:

1. The version of the package changes when changing the distribution release. `apt-get install bash` can give entirely different bits on Ubuntu 24.04 vs 26.04.
1. The version of the package can change even _without_ changing the release. `apt-get install bash` can give a different version running today vs yesterday or tomorrow on the same release, as the `-updates` and `-security` pockets move.

It is possible to mitigate, but not completely solve, the above issue by adding a specific version:

    ```sh
    apt-get install bash=5.2.37-1ubuntu1
    ```

The above does not completely solve it, as the public archive only keeps the most recent version of a package: if the
source installed version `5.2.37-1ubuntu1`, but the most recent update is `5.2.37-1ubuntu1.1`, then the one used may no longer be available.

In order to resolve this issue, both the external/upstream `linuxkit/*` packages and the `lfedge/eve-*` packages in this repository follow the same principles.

1. Create a base image that acts as a package cache: `lfedge/eve-ubuntu` for EVE packages and `linuxkit/alpine` for linuxkit packages. These are used as the base `FROM` for downstream images.
1. All packages included in the composed EVE image **must** use `FROM lfedge/eve-ubuntu` or, in the case of linuxkit packages, `FROM linuxkit/alpine`, in their `Dockerfile`. `FROM ubuntu` or `FROM alpine` is strictly forbidden.
1. The base images download all necessary packages needed by downstream and cache them: `lfedge/eve-ubuntu` resolves everything against one timestamp of the [Ubuntu snapshot service](https://snapshot.ubuntu.com), `linuxkit/alpine` against the Alpine mirrors.
1. When downstream images need to install packages, they install solely from the cache in the base image.

The base images - `lfedge/eve-ubuntu` and `linuxkit/alpine` - act as pinning cache, with precise versions and bits of each package.

Only when the cache is regenerated, i.e. when `lfedge/eve-ubuntu` or `linuxkit/alpine` is rebuilt, can these change.

To make this more concrete, we will walk through a specific example, `lfedge/eve-mkconf`, which is based in [../pkg/mkconf](../pkg/mkconf/).

The key parts of the Dockerfile are as follows:

    ```dockerfile
    FROM lfedge/eve-ubuntu:9a6ebfad80ca4d18950553f8bf2c01a068869805 AS build
    ENV PKGS="mtools dosfstools"
    RUN eve-ubuntu-deploy.sh
    ...
    FROM scratch
    COPY --from=build /out /
    ```

Note the key elements:

* The final image is based on `scratch`
* The `FROM` image for installing necessary packages is **not** `ubuntu:resolute`, but rather the EVE base image `lfedge/eve-ubuntu:9a6ebfad80ca4d18950553f8bf2c01a068869805`
* The packages needed to be installed are set in the `PKGS` environment variable: `mtools dosfstools`
* Packages needed only to build would be set in the `BUILD_PKGS` environment variable

The usage of the `PKGS` and `BUILD_PKGS` environment variables and the script `eve-ubuntu-deploy.sh` is a simplified way to install packages.
It is similar to calling `apt-get install mtools dosfstools`, but does so from the mirror inside the base image, never from the network.

* Those packages listed in `BUILD_PKGS` are installed and available during the build of the `Dockerfile`.
* Those packages listed in `PKGS` are installed into `/out/`, the Ubuntu rootfs that becomes the final image.

## How the base images are built

The two base images, linuxkit and EVE, use different caching techniques.

### EVE Ubuntu base image

The EVE base image is `lfedge/eve-ubuntu`, source at [../pkg/ubuntu](../pkg/ubuntu/), described in [UBUNTU.md](./UBUNTU.md).

The list of packages to mirror is in [../pkg/ubuntu/mirrors](../pkg/ubuntu/mirrors/): one directory per Ubuntu release, with a
file `main` for every architecture and `main.<arch>` files for architecture specific packages. The build resolves the
transitive dependency closure of those lists with apt against `https://snapshot.ubuntu.com/ubuntu/<timestamp>`, downloads
the `.deb` files into `/mirror/archives` and indexes them with `dpkg-scanpackages`. The same timestamp is used to bootstrap
the `/out` rootfs and to install the builder's toolchains, so one `UBUNTU_SNAPSHOT` in the Dockerfile pins every bit of the image.

The snapshot service keeps every package version it ever served, so unlike a mirror of the moving archive, a rebuild of the
image with the same timestamp and lists reproduces the same package set.

### Linuxkit alpine cache image

The alpine cache image is `linuxkit/alpine`, source at
[https://github.com/linuxkit/linuxkit/tree/master/tools/alpine](https://github.com/linuxkit/linuxkit/tree/master/tools/alpine).

The list of packages to install is in the root directory of the package as [packages](https://github.com/linuxkit/linuxkit/tree/master/tools/alpine/packages).

The linuxkit cache does not distinguish between repositories, e.g. `main` vs `community`. It also does not have support for installing from other versions of
alpine, for example, if running on alpine 3.15 and needing a package only available in alpine 3.16.

Optionally, there can be files with architecture extensions, which will be installed only on those architectures. For example:

* `packages.aarch64` - list packages be installed only on `aarch64`.

The linuxkit cache alpine image provides several additional checks to ensure reproducibility.

Upon running a build, the build process updates `versions.<arch>` with:

* the actual version of each package installed to cache
* the hash of the cached content

Specifically, at the end of the `Dockerfile` build, the following command is run:

    ```sh
    echo Dockerfile /lib/apk/db/installed $(find /mirror -name '*.apk' -type f) $(find /go/bin -type f) | xargs cat | sha1sum | sed 's/ .*//' | sed 's/$/-'"${TARGETARCH}"'/' > /etc/alpine-hash-arch
    ```

This creates, inside the image, a file `/etc/alpine-hash-arch` with a single line. The contents of that line are `<hash>-<arch>` where:

* `<hash>` is the sha1 hash of the entire contents of:
  * the apk package database
  * all of the apk cached files
  * all of the golang binaries
* `<arch>` is the architecture of the image

For example, as of this writing, the contents of `/etc/alpine-hash-arch` on x86_64, a.k.a. amd64, are:

    ```sh
    linuxkit/alpine:c9b0f6a435b663b98952d67f4c6f105c310d0a21-amd64
    ```

and the file [versions.x86_64](https://github.com/linuxkit/linuxkit/tree/master/tools/alpine/versions.x86_64) begins with:

    ```sh
    # linuxkit/alpine:c9b0f6a435b663b98952d67f4c6f105c310d0a21-amd64
    # automatically generated list of installed packages
    abuild-3.8.0_rc4-r0
    alpine-baselayout-3.2.0-r16
    alpine-keys-2.4-r0
    apk-tools-2.12.7-r0
    argon2-libs-20190702-r1
    argp-standalone-1.3-r4
    ```

## Summary

1. EVE itself can be reproduced reliably because it is built based on effectively immutably tagged OCI container images, based primarily on git tree hashes.
1. Each package can be reproduced reliably because it sources only:
   * specific versioned software from the Internet
   * go modules with hashes
   * hash-based other container images
   * Ubuntu packages solely from the EVE base image, apk packages solely from the linuxkit alpine cache image
1. The EVE base image and the linuxkit alpine cache can be used as an immutable cache, and change only when specifically selected to do so
1. The images are functionally reproducible, rather than precisely reproducible, because of potential variants in file timestamps and random data used
