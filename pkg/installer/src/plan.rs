/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#![allow(dead_code)] // consumed by SP-2c (execution) and SP-3 (TUI); not wired to the binary yet.

use serde::Serialize;

use crate::config::{Fs, InstallConfig, RaidLevel};
use crate::disk::Disk;

/// Facts about the running machine that the pure planner needs. Gathered by the
/// caller (SP-2c) from /root/etc/eve-hv-type, /root/etc/eve-platform, /proc/meminfo.
#[derive(Debug, Clone)]
pub struct HardwareFacts {
    pub memory_gb: u64,
    pub eve_flavor: String, // "kvm" | "xen" | "k"
    pub platform: String,
}

/// Where the ext4 persist filesystem lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PersistDevice {
    P3OnInstallDisk,       // make-raw creates P3 on the install disk
    SeparateDisk(String),  // /dev path of a separate single persist disk
}

/// A member of a ZFS persist pool. `P3OnInstallDisk` is symbolic — SP-2c resolves
/// the actual P3 partition path after make-raw runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PoolMember {
    P3OnInstallDisk,
    WholeDisk(String),     // /dev path
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum NukePlan {
    None,
    Disks(Vec<String>),
    AllDisks,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PersistPlan {
    Ext4 { device: PersistDevice },
    Zfs { members: Vec<PoolMember>, raid: RaidLevel, clustered: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallPlan {
    pub fs: Fs,
    pub make_raw_parts: Vec<String>,
    pub persist: PersistPlan,
    pub nuke: NukePlan,
    pub advisories: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum PlanOutcome {
    Ready(InstallPlan),
    Rejected(String),
}

/// Minimum number of pool disks a raid level requires.
pub fn raid_min_disks(level: RaidLevel) -> usize {
    match level {
        RaidLevel::None => 1,
        RaidLevel::Raid1 => 2,
        RaidLevel::Raid5 => 3,
        RaidLevel::Raid6 => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raid_min_disks_values() {
        assert_eq!(raid_min_disks(RaidLevel::None), 1);
        assert_eq!(raid_min_disks(RaidLevel::Raid1), 2);
        assert_eq!(raid_min_disks(RaidLevel::Raid5), 3);
        assert_eq!(raid_min_disks(RaidLevel::Raid6), 4);
    }

    #[test]
    fn plan_types_construct_and_serialize() {
        let p = InstallPlan {
            fs: Fs::Ext4,
            make_raw_parts: vec!["efi".into()],
            persist: PersistPlan::Ext4 { device: PersistDevice::P3OnInstallDisk },
            nuke: NukePlan::None,
            advisories: vec![],
        };
        // derives present; serializes without panicking
        assert!(serde_json::to_string(&p).is_ok());
        assert_eq!(PlanOutcome::Ready(p.clone()), PlanOutcome::Ready(p));
    }
}
