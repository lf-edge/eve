# pkg/sources

This package will build a docker image that will store the collected_sources.tar.gz which is needed for SBOM comparison. The docker image will be pushed to `eve-sources` repo under lfedfge on dockerhub.

Collected_sources.tar.gz includes:

* alpine, kernel and golang packages.
* A manifest file collected_sources_manifest.csv that holds the metadata for all the packages.

## Usage

```bash
make -e V=1 HV=${{ matrix.hv }} ZARCH=${{ matrix.arch }} LINUXKIT_PKG_TARGET=push publish_sources
```