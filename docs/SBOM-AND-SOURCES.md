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
$ docker run --rm lfedge/eve:9.9.0-kvm sbom
```

For each _release_ of EVE-OS, one SPDX json file per image variant is attached to the release page on github. This normally is at the path `https://github.com/lf-edge/eve/releases/tag/<release>`, for example `https://github.com/lf-edge/eve/releases/tag/17.6.0`. Each asset is named `<arch>.<hv>.<platform>.rootfs.spdx.json`, for example `amd64.kvm.generic.rootfs.spdx.json`. Older releases carry no SPDX asset; their SBoM is available through the container's `sbom` command.

There is one SBoM per image variant rather than one per release because the package set differs between variants: the `k` hypervisor flavor adds the kube service, the NVIDIA platforms add their own drivers, and the kernel version is selected per architecture and platform in `kernel-version.mk`.

### Sources

The sources for EVE-OS are collected in a gzipped tar file

The format of the tar file is one directory per source type, with the name of the directory being the source type.
Inside each directory is either a directory or file with the sources for that type.

As of this writing, the types are: golang, debian, kernel. The sources file also contains a manifest of all packages in
the sources file.

#### golang

Golang sources are collected in the `golang/` directory of the tar.gz file.

Each golang dependency, including its version number, is in one zip file per dependency. Because golang
packages normally are URLs, e.g. `golang.org/x/sync`, which includes slashes in the name, the zip file
changes all `/` characters to `_`. The version is included after the `@` character, following standard golang convention.

Thus, the path to `golang.org/x/sync` version `v0.1.0` is at the path `golang/golang_org_x_sync@v0.1.0.zip`.

#### debian

Ubuntu package sources are collected in the `debian/` directory of the tar.gz file.

Each source package of any Ubuntu package installed anywhere on the system, including in containers, is in one directory per
source package-version combination, holding the `.dsc` file, the upstream tarball and the Ubuntu packaging tarball as the
snapshot of the Ubuntu archive the image was built from serves them.

For example, the source of package `libc6` version `2.43-2ubuntu2.4` is `glibc` and is in the directory
`glibc.2.43-2ubuntu2.4`. The package name is until the first `.`, the version after it.

The manifest file `collected_sources_manifest.csv` contains a list of all packages in the sources tar.gz
file. It is a comma-separated value file, with the following columns:

* package type: `kernel`,`golang`,`debian`
* package name and version:
  * for debian, `<source>@<version>`, e.g. `glibc@2.43-2ubuntu2.4`
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
