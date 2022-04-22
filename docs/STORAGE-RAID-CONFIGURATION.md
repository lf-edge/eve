# EVE-OS supported RAID configuration(s)

| RAID Level | Separate EVE-OS disk | Minimum number of disks required | Example Grub Configuration              |
| ---------- | -------------------- | -------------------------------- | --------------------------------------- |
| raid0      | Not mandatory        |  1                               | eve_install_zfs_with_raid_level = none
| (stripe)   |                      |                                  | Single disk config:
|            |                      |                                  | eve_install_disk=sda
|            |                      |                                  |
|            |                      |                                  | Multiple disk config:
|            |                      |                                  | eve_install_disk=sda
|            |                      |                                  | eve_persist_disk=sda,sdb,sdc
|            |                      |                                  |
|            |                      |                                  | Please note that sda should be listed in
|            |                      |                                  | both install and persist disk
|            |                      |                                  | NOTE: The parameter value none passed to zfs
|            |                      |                                  | raid level  implies that there is no raid support.
|            |                      |                                  | If multiple disks are used for persist install,
|            |                      |                                  | that results in striping.
|            |                      |                                  |
| raid1      | Mandatory            |  2                               | eve_install_zfs_with_raid_level = raid1
| (mirror)   |                      |                                  | eve_install_disk=sda
|            |                      |                                  | eve_persist_disk=sdb,sdc
|            |                      |                                  |
| raid5      | Mandatory            |  3                               | eve_install_zfs_with_raid_level = raid5
| (raidz1)   |                      |                                  | eve_install_disk=sda
|            |                      |                                  | eve_persist_disk=sdb,sdc,sdd
|            |                      |                                  |
| raid6      | Mandatory            |  4                               | eve_install_zfs_with_raid_level = raid6
| (raidz2)   |                      |                                  | eve_install_disk=sda
|            |                      |                                  | eve_persist_disk=sdb,sdc,sdd,sde
