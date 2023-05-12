# pkg/sources

This package will build a docker image that will store the collected_sources.tar.gz which is needed for SBOM comparison. The docker image will be pushed to `eve-sources` repo under lfedfge on dockerhub.

Collected_sources.tar.gz includes:

* alpine, kernel and golang packages.
* A manifest file collected_sources_manifest.csv that holds the metadata for all the packages.

### Workflow
- Depends on `collected_sources` which will generate the tar.gz file under `dist/amd64/<path>/sources`
- Will copy the Dockerfile and build.yml under `dist/amd64/<path>/sources`
- The Dockerfile will copy the collected_sources.tar.gz from `dist/amd64/<path>/sources` into it's file system.
- The image will be pushed to lfedge/eve-sources in dockerhub.

### Usage: collected_sources

```bash
make collected_sources

# file path
dist/amd64/0.0.0-master-dd487a54-dirty-2023-05-12.12.44/sources/collected_sources.tar.gz
```

### Usage(local): publish_sources(build only. no push to lfedge/eve-sources)
```bash
make -e V=1 LINUXKIT_PKG_TARGET=build publish_sources
```

### output
An image containing the collected_sources.tar.gz will be pushed to remote lfedge/eve-sources
