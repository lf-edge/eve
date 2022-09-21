# Custom Build

This document describes how to modify parts of eve-os so you can build a custom image for your own purposes.

Before reading this document and attempting a change, we strongly recommend you familiarize yourself with how the
normal eve-os build process works, as described in [BUILD.md](./BUILD.md).

## Overview

The build process involves two stages:

1. Build packages
1. Build a bootable eve-os image

The packages built as part of the normal eve-os Continuous Integration process are distributed publicly via Docker Hub.
The bootable eve-os image is distributed publicly to Docker Hub as well.

You can make changes in one or both of the following ways:

* Modify a package and then build eve-os to include that package
* Modify the eve-os build to include external packages

## Modify a Package

To modify a package, you simply change the source of the package as you see fit.

For example, to modify grub, change the desired source in [pkg/grub/](../pkg/grub); to modify the kernel,
change the desired source in [pkg/kernel/](../pkg/kernel).

Once you are done modifying the package, from the root directory of eve, build the package:

```sh
make pkg/<package>
```

For example, `make pkg/pillar` or `make pkg/guacd`.

Some packages require special treatment in the form of extra steps after build. Those should be invoked with their dedicated targets.
As of this writing, only `pkg/kernel` is subject to this special treatment, and should be invoked as:

```sh
make kernel
```

The `make` command will use linuxkit to build an OCI image based on the contents of the directory, e.g. `pkg/guacd`. The tag
on the image is based on the [git tree hash](https://git-scm.com/docs/git-ls-tree) of the directory.

If the directory has uncommitted changes, the resultant tag will include `-dirty`. It is your choice whether to accept
the `-dirty` tag, or to commit your changes.

### Pushing to Registry

The package build will **not** push the image out to any OCI registry. The resultant image will be kept locally, on your machine,
in the linuxkit cache directory.

If you wish to push it out, you must:

1. modify the `build.yaml` in the directory to indicate the `org` and `image` to use.
1. run `make pkg/<path> LINUXKIT_PKG_TARGET=push` to indicate that you want to push it, which will build _and_ push the image.

### Building eve-os Using the Modified Package

With the package modified, you can run:

```sh
make eve
```

This will:

1. Find the current value of each `pkg/` directory.
1. Generate a proper eve-os `rootfs.yaml` based on the template located in [images/](../images) and the updated values.
1. Build an eve-os image.

## Modify the eve-os Build

The eve-os build itself utilizes the instructions in the yaml files, primarily templates, located in [images/](../images).

You can modify any of those files and then run `make eve`.

Note that the entries in those files are either static, i.e. OCI image references, or template tags, which normally are all upper-cased
and end in `_TAG`. For example, `DOM0ZTOOLS_TAG`, `KERNEL_TAG`, `RNGD_TAG`. These are the ones that are replaced by the calculated tags
when running `make eve`.

You can replace any tag, static or dynamic, and then run `make eve`. Keep in mind that replacing dynamic tags means that you will not get
the auto-generated templating.
