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

The other image names are templated. These are all captialized, and end in `_TAG`. For example:

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

As described above in [EVE OS Images][EVE OS Images], all of the packages used to compose a bootable EVE image
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
|OS packages|`apk add`|See next section|

It is possible for human error in any of the above to slip through. EVE uses peer review and maintainer approval to reduce the probabilities of
any non-reproducible source slipping in.

Further, the EVE project is exploring additional gates. These include:

* Contributors certifying on each Pull Request that they have not used non-reproducible sources.
* Regular automated audits of all `pkg/` sources.
* CI scans of `pkg/` sources.

## Linux Packages

The primary source for many software packages in Linux is the OS packaging system. All of the OCI images used in EVE are based on
[Alpine](https://hub.docker.com/_/alpine), which uses the [apk package manager](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper).

For example, to install bash:

```sh
apk add bash
```

Alpine packages creates unique challenges for reproducibility. Specifically:

1. The version of the package changes when changing the alpine version. `apk add bash` can give entirely different bits when running on `alpine:3.15` vs `alpine:3.16`.
1. The version of the package can change even _without_ changing the alpine version. `apk add bash` can give a different version running today on `alpine:3.16` vs yesterday or tomorrow on the same base `alpine:3.16`.

It is possible to mitigate, but not completely solve, the above issue by adding a specific version:

```sh
apk add bash=5.1.16-r2
```

The above does not completely solve it, as sometimes alpine packages change their bits _even for the same version_. Thus, running
`apk add bash=5.1.16-r2` on the same base `alpine:3.16` can give different bits on different days. Alpine packages are changed "under the covers"
when bugs are found or updates are provided.

In addition, often the public Alpine apk repositories only contain the most recent versions of packages. Thus, if the source
installed bash version `5.1.16-r2`, but the most recent update is `5.1.16-r3`, then the one used, `5.1.16-r2`, may not be available.

In order to resolve this issue, both the external/upstream `linuxkit/*` packages and the `lfedge/eve-*` packages in this repository follow the same principles.

1. Create an alpine "cache" image: `linuxkit/alpine` and `lfedge/eve-alpine`. These are used as the base `FROM` for downstream images.
1. All packages included in the composed EVE image **must** use `FROM lfedge/eve-alpine` or, in the case of linuxkit packages, `FROM linuxkit/alpine`, in their `Dockerfile`. `FROM alpine` is strictly forbidden.
1. The cache images source from upstream alpine, download all necessary apk packages needed by downstream, `lfedge/eve-alpine` for EVE packages and `linuxkit/alpine` for linuxkit packages, and cache them.
1. When downstream images need to install packages, they run `apk add package` which sources it solely from the cache in the cache image.

The cache images - `lfedge/eve-alpine` and `linuxkit/alpine` - act as pinning cache, with precise versions and bits of each package.

Only when the cache is regenerated, i.e. when `lfedge/eve-alpine` or `linuxkit/alpine` is rebuilt, can these change.

Further, the caches maintain hashes of the local cache contents, to ensure that any changes are known and captured.

To make this more concrete, we will walk through a specific example, `lfedge/eve-dom0-ztools`, which is based in [../pkg/dom0-ztools](../pkg/dom0-ztools/).

The key parts of the Dockerfile are as follows:

```dockerfile
FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 as zfs
ENV BUILD_PKGS git patch ca-certificates util-linux build-base gettext-dev libtirpc-dev automake autoconf \
    libtool linux-headers attr-dev e2fsprogs-dev glib-dev openssl-dev util-linux-dev coreutils
ENV PKGS ca-certificates util-linux libintl libuuid libtirpc libblkid libcrypto1.1 zlib
RUN eve-alpine-deploy.sh
...
FROM scratch
COPY --from=zfs /out/ /
ADD rootfs/ /
```

Note the key elements:

* The final image is based on `scratch`
* The `FROM` image for installing necessary packages is **not** `alpine:3.16`, but rather the eve alpine cache image `lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52`
* The packages needed to be installed are set in the `PKGS` environment variable: `ca-certificates util-linux libintl libuuid libtirpc libblkid libcrypto1.1 zlib`
* The build packages needed to be installed are set in the `BUILD_PKGS` environment variable: `git patch ca-certificates util-linux build-base gettext-dev libtirpc-dev automake autoconf libtool linux-headers attr-dev e2fsprogs-dev glib-dev openssl-dev util-linux-dev coreutils`

The usage of the `PKGS` and `BUILD_PKGS` environment variables and the script `eve-alpine-deploy.sh` is a simplified way to install packages.
It is similar to calling:
`apk add ca-certificates util-linux libintl libuuid libtirpc libblkid libcrypto1.1 zlib`, but
do so from the cache.

* Those packages listed in `BUILD_PKGS` are installed and available during the build of the `Dockerfile`.
* Those packages listed in `PKGS` are installed and available during the build of the `Dockerfile`, but are also available in `/out/`. This enables copying them over to the final image.

## How the Alpine cache image is built

The two alpine cache images, linuxkit and EVE, use similar but slightly different caching techniques.
Both use the official apk local cache feature described [here](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper#Local_Cache).

Both follow the same primary process in the Dockerfile:

1. Install the tools necessary for working with apk
1. Create a local mirror directory and set it up according to the above documentation
1. Go through the list of packages required for all platforms, as well as platform specific, and install it to local cache
1. Change the apk configuration so that any downstream container image that uses it and runs `apk add` will get it from cache, rather than the Internet

### EVE alpine cache image

The EVE alpine cache image is `lfedge/eve-alpine`, source at [../pkg/alpine](../pkg/alpine/)

The list of packages to install is in [../pkg/alpine/mirrors](../pkg/alpine/mirrors/). There is a subdirectory for each version of alpine package
repository we want, for example [../pkg/alpine/mirrors/3.16](../pkg/alpine/mirrors/3.16). Underneath those is a file for each repository type.
Every package listed in those files will be installed to the cache.

* `main` - list of packages to cache from the `main` package repository for all architectures
* `community` - list of packages to cache from the `community` package repository for all architectures

Optionally, there can be files with architecture extensions, which will be installed only on those architectures. For example:

* `main.aarch64` - list packages from `main` to be installed only on `aarch64`.

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

```
linuxkit/alpine:c9b0f6a435b663b98952d67f4c6f105c310d0a21-amd64
```

and the file [versions.x86_64](https://github.com/linuxkit/linuxkit/tree/master/tools/alpine/versions.x86_64) begins with:

```
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
   * apk packages solely from the EVE or linuxkit alpine cache image
1. The EVE or linuxkit alpine cache can be used as an immutable cache, and changes only when specifically selected to do so
1. The images are functionally reproducible, rather than precisely reproducible, because of potential variants in file timestamps and random data used
