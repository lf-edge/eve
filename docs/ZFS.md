# ZFS (highly experimental support)

ZFS provides a rich set of functionality but at a cost of extra
resource usage. Currently ARC (Adaptive Replacement Cache) size is
limited to `min(256 MiB + 0.3% of total zpool size, 20% of system RAM)` but at least 384
MiB. This RAM is included in the memory EVE reserves for its own operational needs.
Thus would this memory not be available for allocation for applications.

If system does not have enough memory to satisfy the limit mentioned
above, severe performance degradation can occur on random access
workflows.

## Performance tunings applied

`primarycache=metadata` - allows to keep arc cache size low. The primary
use-case of zfs is zvol attached to a VM. And VM already does cache
it's data, furthermore it knows better what to cache.

`recordsize=16k` - is a sweet spot between constantly having sub-blocks
updates, and good compression ratio.

`compression=zstd` - is a less cpu intensive algorithm, with not too big
compromise on compression ratio

`redundant_metadata=most` - will reduce the number of copies of the
indirect blocks at the higher levels. This can greatly cut the amount
of data that must be written, resulting in better performance.

Multiple tunables to better regulate how fast ZFS can accept
requests. This along helped mediate maximum latency on parallel access
with small ARC:

```bash
zfs_vdev_async_write_active_min_dirty_percent = 10
zfs_vdev_async_write_active_max_dirty_percent = 30
zfs_delay_min_dirty_percent = 40
zfs_delay_scale = 800000
zfs_dirty_data_max = 50% of zfs_arc_max
zfs_dirty_data_sync_percent = 15
```

The following tunables are hardcoded and are optimized values for SSD/NVMe based pools.
Please note that these tunables may not work optimally for HDD based pools.
WIP to dynamically adjust these parameters depending on the pool type.

```bash
zfs_vdev_sync_read_min_active = 35
zfs_vdev_sync_read_max_active = 35
zfs_vdev_sync_write_min_active = 35
zfs_vdev_sync_write_max_active = 35
zfs_vdev_async_read_min_active = 1
zfs_vdev_async_read_max_active = 10
zfs_vdev_async_write_min_active = 1
zfs_vdev_async_write_max_active = 10
```

### Minimum recommended system requirements

Minimum recommended system requirements to install ZFS storage is 32GB memory and 3 physical disks set in eve_persist_disk.
eve_install_skip_zfs_checks should be set in installation config to override the requirement check for experimental installs.

## pkg/zfs — dedicated ZFS userspace package

EVE builds OpenZFS userspace tools and libraries as a dedicated linuxkit
package (`pkg/zfs`). All consumers — `pkg/dom0-ztools`, `pkg/pillar`, and
the GOBUILDER dev container — copy artifacts from this single image instead
of each building ZFS independently.

### Version selection

The ZFS version is set in `kernel-version.mk`:

```makefile
ZFS_VERSION=2.3.3
```

The Makefile derives `ZFS_MAJOR_MINOR` (`2.3`) and selects the matching
`pkg/zfs/build-2.3.yml` variant, which encodes the version in its linuxkit
tag suffix (`<content-hash>-2.3`). To build with a different version:

```shell
make ZFS_VERSION=2.4.1 pkgs
make ZFS_VERSION=2.4.1 pkg/zfs
```

Available versions have a corresponding `pkg/zfs/build-<major.minor>.yml`
file. Adding a new version requires adding that file and a matching entry in
`kernel-version.mk`.

### How consumers reference pkg/zfs

Packages that depend on `pkg/zfs` use `FROM ZFS_TAG` in their
`Dockerfile.in`. The `ZFS_TAG` placeholder is resolved to the fully-qualified
image reference by `tools/parse-pkgs.sh` before linuxkit runs, generating the
actual `Dockerfile`. This means linuxkit sees a concrete image name in the
`FROM` line, so it can resolve the dependency from its local content-addressed
cache without requiring a registry push.

See [PACKAGE-DEPS.md](./PACKAGE-DEPS.md) for how the build system detects
when `pkg/zfs` (or any other dependency) has been rebuilt and forces
consumers to rebuild accordingly.
