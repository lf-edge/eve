# ZFS (highly experimental support)

ZFS provides a rich set of functionality but at a cost of extra
resource usage. Currently ARC (Adaptive Replacement Cache) size is
limited to
`min(256 MiB + 0.3% of total zpool size, 20% of system RAM)`
but at least 384 MiB. This RAM is included in the memory EVE reserves
for its own operational needs. Thus would this memory not be available
for allocation for applications.

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

The following tunables are hardcoded and are optimized values for
SSD/NVMe based pools. Please note that these tunables may not work
optimally for HDD based pools. WIP to dynamically adjust these
parameters depending on the pool type.

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

Minimum recommended system requirements to install ZFS storage is
32GB memory and 3 physical disks set in eve_persist_disk.
eve_install_skip_zfs_checks should be set in installation config to
override the requirement check for experimental installs.

## Storage maintenance

### Pool TRIM (EVE-k only)

On EVE-k (kubevirt/Longhorn) nodes the persist pool is backed by NVMe
devices. ZFS does not automatically notify the NVMe controller of freed
block ranges; without periodic TRIM the device's garbage-collection
table grows and write amplification increases.

EVE runs a rate-limited `zpool trim -r <rate> persist` on a recurring
cron schedule. ZFS applies the rate to each disk (leaf vdev), so with the
default of 1.5 MiB/s each disk trims at up to 1.5 MiB/s and a pool of N
disks at up to N times that. Each TRIM command is capped at 16 MiB by the
`zfs_trim_extent_bytes_max` module parameter, which is set at boot.
There is no boot-time trim: an unthrottled trim of the whole free space
keeps the disk saturated for hours and stalls application I/O. A trim interrupted by a reboot resumes
on its own; at startup, and whenever the rate is changed, zfsmanager
suspends it and restarts it at the configured rate, so a trim started
without a limit by an older EVE is throttled too.
The restart keeps the trim's progress, but the start time shown by
`zpool status -t persist` becomes the time of the last boot.
The schedule and rate are operator-configurable:

| Config key | Default | Effect |
| --- | --- | --- |
| `timer.zfs.pool.trim.cron` | `0 3 * * 6,0` | Sat/Sun at 03:00 |
| `storage.zfs.pool.trim.rate.bytespersec` | `1572864` | 1.5 MiB/s per disk, about a week per TB of free space on the disk |

Set the cron spec to an empty string to disable the scheduled trim.

A pass over a 4 TB disk takes about a month at the default rate; raise the
rate to finish sooner at the cost of more I/O latency while it runs.

The trim starts only if the device is powered on at the scheduled minute;
a missed slot is not caught up. Devices that are routinely off at 03:00 on
weekends should use a time when they are on. One trigger a month is
enough, e.g. `0 12 1 * *` for noon on the 1st. A trim already in progress
keeps running, so a pass that spans several triggers is not restarted.

`zpool trim` returns immediately; the actual work runs in the
background. Progress is visible via `zpool status -t persist`.

### Vault fstrim (EVE-k only)

On EVE-k nodes `/persist/vault` is an ext4 filesystem on a ZFS zvol.
When files are deleted, ext4 marks the blocks as free but does not
notify ZFS. The zvol retains the blocks as allocated, inflating
`logicalused` on the persist pool and causing EVE to overestimate its own
disk usage. In severe cases this can incorrectly trigger maintenance
mode.

EVE runs `fstrim /persist/vault` at boot (to drain any backlog) and
then on a recurring cron schedule:

| Config key | Default | Effect |
| --- | --- | --- |
| `timer.vault.trim.cron` | `0 2 * * 6,0` | Sat/Sun at 02:00 |
| `timer.vault.trim.max.secs` | `1800` | Timeout in seconds; `0` = unlimited |

Set `timer.vault.trim.cron` to an empty string to disable the
scheduled fstrim. The boot-time fstrim always runs regardless of this
setting.

The two maintenance operations are staggered by default to avoid
overlap:

| Time | Operation |
| --- | --- |
| 02:00 Sat/Sun | Vault fstrim |
| 03:00 Sat/Sun | Pool-level NVMe TRIM |

### Observing trim activity

#### Pubsub status (live and collect-info)

Trim state is published to pubsub and captured in collect-info bundles,
making it available for post-mortem analysis without log grepping.

**Vault fstrim** — `vaultmgr` publishes to `VaultStatus`:

```sh
cat /run/vaultmgr/VaultStatus/vaultmgr.json \
  | grep -A4 TrimStatus
```

| Field | Meaning |
| --- | --- |
| `TrimStatus.LastStartTime` | fstrim start; zero if never run this boot |
| `TrimStatus.LastEndTime` | When it completed; zero while in progress |
| `TrimStatus.LastError` | Error string on failure; empty on success |

**ZFS pool trim** — `zfsmanager` publishes to `ZFSPoolStatus`:

```sh
cat /run/zfsmanager/ZFSPoolStatus/persist.json \
  | grep -A2 TrimStatus
```

| Field | Meaning |
| --- | --- |
| `TrimStatus.LastStartTime` | When `zpool trim` last started a trim this boot |

Pool trim end time is not published — `zpool trim` returns immediately
and the work continues in the background. Use `zpool status -t persist`
to check completion:

```sh
zpool status -t persist
```

#### Agent logs

**Vault fstrim** (`vaultmgr` agent, Notice level):

```sh
grep -i "TrimVault\|fstrim" /persist/newlog/agentlog/vaultmgr.log*
```

| Log message | Meaning |
| --- | --- |
| `TrimVault: starting fstrim /persist/vault (timeout Xs)` | Run started |
| `TrimVault: fstrim /persist/vault completed in Xs` | Success |
| `TrimVault: fstrim /persist/vault failed after Xs: ...` | Failure |
| `startVaultTrimSchedule: scheduled trim starting` | Cron tick fired |

**ZFS pool trim** (`zfsmanager` agent, Notice level):

```sh
grep -i "runPoolTrimSchedule" /persist/newlog/agentlog/zfsmanager.log*
```

| Log message | Meaning |
| --- | --- |
| `runPoolTrimSchedule: zpool trim persist initiated` | Command accepted |
| `runPoolTrimSchedule: scheduled trim starting` | Cron tick fired |
| `runPoolTrimSchedule: zpool trim persist already in progress` | Cron tick during a running trim; it continues |
| `runPoolTrimSchedule: resumed trim of persist at 1572864 bytes/s` | Startup re-issued a running trim at the rate limit |
| `runPoolTrimSchedule: zpool trim persist: <error>` | Failure |
