# SBoM and Sources

EVE-OS comes with a [software bill of materials (SBoM)](https://en.wikipedia.org/wiki/Software_supply_chain)
and sources for all of its dependencies.

## Finding SBoM and Sources

### SBoM

The SBoM provides by EVE-OS is in the [SPDX](https://spdx.github.io/spdx-spec/v2.3/) format, delivered as a json file.

The SPDX json file is available from two locations:

* EVE-OS container
* github release page

For each build of EVE-OS, it can be retrieved by running the EVE-OS container and passing it the command `sbom`.

For example,

```bash
$ docker run --rm lfedge/eve:9.9.0 sbom
```

For each _release_ of EVE-OS, the sbom is listed on the release page on github. This normally is at the path `https://github.com/lf-edge/eve/releases/tag/<release>`, for example `https://github.com/lf-edge/eve/releases/tag/9.12.0`.

### Sources

The sources for EVE-OS are collected in a gzipped tar file

The format of the tar file is one directory per source type, with the name of the directory being the source type.
Inside each directory is either a directory or file with the sources for that type.

As of this writing, the types are: golang, alpine, kernel. The sources file also contains a manifest of all packages in
the sources file.

#### golang

Golang sources are collected in the `golang/` directory of the tar.gz file.

Each golang dependency, including its version number, is in one zip file per dependency. Because golang
packages normally are URLs, e.g. `golang.org/x/sync`, which includes slashes in the name, the zip file
changes all `/` characters to `_`. The version is included after the `@` character, following standard golang convention.

Thus, the path to `golang.org/x/sync` version `v0.1.0` is at the path `golang/golang_org_x_sync@v0.1.0.zip`.

#### alpine

Alpine sources are collected in the `alpine/` directory of the tar.gz file.

Each alpine package installed anywhere on the system, including in containers, is in one directory per package-version
combination. The directory name also contains the specific commit in github.alpinelinux.org for that version.

For example, package `alpine-baselayout` version `3.2.0-r16` is in the directory
`alpine-baselayout.3.2.0-r16.8a8c96a0ea2fcd824c361aa4438763fa33ee8ca0`, while version `3.2.0-r23` is in the directory
`alpine-baselayout.3.2.0-r23.348653a9ba0701e8e968b3344e72313a9ef334e4`.
The package name is until the first `.`, the commit is after the last `.`.

Inside the directory is all of the sources as declared by the package's `APKBUILD` file.

#### kernel

Kernel sources are located in the `kernel/` directory of the tar.gz file.

All kernel sources are pulled directly from the Internet, via a URL to a Web site or git repository. In the case
of a file, the original file format is preserved. For example, the sources to kernel version `5.10.121` are in a
`.tar.xz` file.

In the case of a git repository, the source at the specific commit used is retrieved as a tar file. For example,
the source to the kernel module `github.com/brektrou/rtl8821CU` commit `8c2226a7` is retrieved from
`https://github.com/brektrou/rtl8821CU/tarball/8c2226a7` and saved as a single tar file.

File names in `kernel/` all are the URL to the source, excluding the initial protocol, and with all `/` characters
replaced with `_`. For example, the kernel source at `https://www.kernel.org/pub/linux/kernel/v5.x/linux-5.10.121.tar.xz`
is in the sources tar.gz file at `kernel/www.kernel.org_pub_linux_kernel_v5.x_linux-5.10.121.tar.xz`.

#### manifest

The manifest file `collected_sources_manifest.csv` contains a list of all packages in the sources tar.gz
file. It is a comma-separated value file, with the following columns:

* package type: `kernel`,`golang`,`alpine`
* package name and version:
  * for alpine, `<name>.<version>.<commit>`, e.g. `vim.8.2.5000-r0.2dc89b8883d747b3d31941c199431489654b9f29`
  * for golang, `<name>@<version>`, e.g. `golang.org/x/crypto-v0.1.0`
  * for kernel, the URL to the source, e.g. `https://www.kernel.org/pub/linux/kernel/v5.x/linux-5.10.121.tar.xz`
* package commit, if any, else version
* path to package in the source tar.gz file, e.g. `kernel/www.kernel.org_pub_linux_kernel_v5.x_linux-5.10.121.tar.xz`

## Generating SBoM and Sources

To generate the SBoM, run `make sbom`. This does the following:

1. Build the eve image components in `dist/<arch>/<release>`, if not yet built
1. Expand the `rootfs.tar` in the directory to a temporary directory
1. Run [syft](https://github.com/anchore/syft) on the temporary directory, outputting the SBoM to `dist/<arch>/<release>/installer/rootfs.spdx.json`
1. Remove the temporary directory

To generate the sources, run `make collected_sources`. This does the following:

1. Build the eve image components in `dist/<arch>/<release>`, if not yet built
1. Run [tools/collect-sources.sh](../tools/collect-sources.sh), which:
   1. Runs individual commands to collect each of the source types
   1. Saves output information to the manifest
   1. Creates the `collected_sources.tar.gz` file in `dist/<arch>/<release>`

## Reconciling SBoM and Sources

The command [tools/compare-sbom-sources](../tools/compare-sbom-sources/) takes as input the SBoM and manifest from the
sources file and reconciles them. It reports total number of packages in each, total overlap, total in one and not the
other, and the specific packages not in both.

To run it, compile the file via `go build` and run it with the SBoM and manifest as arguments. In addition to basic
functionality, it can:

* read directly from the `collected_sources.tar.gz`
* limit comparisons to specific file types
* other capabilities

Run it with `--help` to see options.
