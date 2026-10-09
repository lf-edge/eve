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

/// PLACEHOLDER for the disk-too-small guard. Real check (minimum size computed
/// from make-raw's partition constants, ~24 GiB base) is TODO, likely with SP-4
/// / make-raw unification. The real minimum depends on which parts are present
/// (e.g. whether a `persist` partition is included), hence `_make_raw_parts` is
/// already threaded through even though it's unused today. Returns None
/// (rejects nothing) for now.
fn disk_size_ok(_install: &Disk, _make_raw_parts: &[String]) -> Option<String> {
    None
}

/// Compute the install plan from resolved disks, config, and hardware facts.
/// Pure and total: returns Ready(plan) (possibly with advisories) or
/// Rejected(reason) for dangerous/impossible cases. Never panics.
pub fn plan(
    install: &Disk,
    persist: &[Disk],
    boot: Option<&str>,
    cfg: &InstallConfig,
    hw: &HardwareFacts,
) -> PlanOutcome {
    let boot_bare = boot.map(|b| b.strip_prefix("/dev/").unwrap_or(b));

    // ---- hard rejects: boot disk as a target ----
    if Some(install.name.as_str()) == boot_bare {
        return PlanOutcome::Rejected(format!("install disk {} is the boot disk", install.name));
    }
    for d in persist {
        if Some(d.name.as_str()) == boot_bare {
            return PlanOutcome::Rejected(format!("persist disk {} is the boot disk", d.name));
        }
    }
    if persist.is_empty() {
        return PlanOutcome::Rejected("no persist disk resolved".to_string());
    }

    let mut advisories: Vec<String> = Vec::new();

    // ---- filesystem choice ----
    let multi = persist.len() > 1;
    let fs = if multi {
        if cfg.persist_fs == Some(Fs::Ext4) {
            advisories.push("ext4 cannot span multiple persist disks; using zfs".to_string());
        }
        Fs::Zfs
    } else if cfg.persist_fs == Some(Fs::Zfs) || cfg.zfs_raid_level.is_some() {
        Fs::Zfs
    } else {
        Fs::Ext4
    };
    let clustered = hw.eve_flavor == "k" && fs == Fs::Zfs;
    let raid = cfg.zfs_raid_level.unwrap_or(RaidLevel::None);

    // ---- hard reject: raid needs more pool disks than present ----
    if fs == Fs::Zfs && raid_min_disks(raid) > persist.len() {
        return PlanOutcome::Rejected(format!(
            "raid level {:?} needs at least {} disks, {} selected",
            raid,
            raid_min_disks(raid),
            persist.len()
        ));
    }

    // ---- make_raw_parts (explicit) + persist layout ----
    let install_is_persist_member = persist.iter().any(|d| d.name == install.name);
    let mut make_raw_parts: Vec<String> =
        ["efi", "efi_b", "imga", "imgb", "conf"].iter().map(|s| s.to_string()).collect();
    if install_is_persist_member {
        make_raw_parts.push("persist".to_string());
    }

    // ---- hard reject: disk too small (placeholder no-op) ----
    // Runs after make_raw_parts is built: the size floor depends on which
    // parts are present (e.g. whether a `persist` partition is included).
    if let Some(reason) = disk_size_ok(install, &make_raw_parts) {
        return PlanOutcome::Rejected(reason);
    }

    let persist_plan = match fs {
        Fs::Ext4 => {
            let device = if install_is_persist_member {
                PersistDevice::P3OnInstallDisk
            } else {
                PersistDevice::SeparateDisk(persist[0].path.clone())
            };
            PersistPlan::Ext4 { device }
        }
        Fs::Zfs => {
            let members = persist
                .iter()
                .map(|d| {
                    if d.name == install.name {
                        PoolMember::P3OnInstallDisk
                    } else {
                        PoolMember::WholeDisk(d.path.clone())
                    }
                })
                .collect();
            PersistPlan::Zfs { members, raid, clustered }
        }
    };

    // ---- advisories (soft) ----
    if fs == Fs::Zfs && cfg.skip_zfs_checks != Some(true) {
        if hw.memory_gb < 64 {
            advisories.push(format!("zfs recommends >= 64GB RAM, have {}GB", hw.memory_gb));
        }
        if persist.len() < 3 {
            advisories.push(format!("zfs recommends >= 3 disks, have {}", persist.len()));
        }
    }
    if install.read_only {
        advisories.push(format!("install disk {} is read-only", install.name));
    }
    for d in persist {
        if d.read_only && d.name != install.name {
            advisories.push(format!("persist disk {} is read-only", d.name));
        }
    }

    // ---- nuke ----
    let nuke = if cfg.nuke_all_disks == Some(true) {
        NukePlan::AllDisks
    } else if let Some(list) = cfg.nuke_disks.as_ref().filter(|l| !l.is_empty()) {
        NukePlan::Disks(list.clone())
    } else {
        NukePlan::None
    };

    PlanOutcome::Ready(InstallPlan { fs, make_raw_parts, persist: persist_plan, nuke, advisories })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(name: &str, size: u64, ro: bool) -> Disk {
        Disk {
            name: name.to_string(),
            path: format!("/dev/{name}"),
            kind: "disk".to_string(),
            size_bytes: size,
            transport: None,
            model: None,
            serial: None,
            read_only: ro,
            virtual_dev: false,
            partitions: vec![],
        }
    }
    fn hw(mem: u64, flavor: &str) -> HardwareFacts {
        HardwareFacts { memory_gb: mem, eve_flavor: flavor.to_string(), platform: "generic".to_string() }
    }
    fn ready(o: PlanOutcome) -> InstallPlan {
        match o { PlanOutcome::Ready(p) => p, PlanOutcome::Rejected(r) => panic!("rejected: {r}") }
    }
    const GB: u64 = 1024 * 1024 * 1024;

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

    #[test]
    fn ext4_single_disk_persist_on_install() {
        let vdb = disk("vdb", 40 * GB, false);
        let p = ready(plan(&vdb, &[vdb.clone()], Some("vda"), &InstallConfig::default(), &hw(8, "kvm")));
        assert_eq!(p.fs, Fs::Ext4);
        assert!(p.make_raw_parts.contains(&"persist".to_string()));
        assert_eq!(p.persist, PersistPlan::Ext4 { device: PersistDevice::P3OnInstallDisk });
    }

    #[test]
    fn zfs_explicit_single_disk() {
        let vdb = disk("vdb", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.persist_fs = Some(Fs::Zfs);
        let p = ready(plan(&vdb, &[vdb.clone()], Some("vda"), &cfg, &hw(64, "kvm")));
        assert_eq!(p.fs, Fs::Zfs);
        assert!(p.make_raw_parts.contains(&"persist".to_string()));
        assert_eq!(
            p.persist,
            PersistPlan::Zfs { members: vec![PoolMember::P3OnInstallDisk], raid: RaidLevel::None, clustered: false }
        );
    }

    #[test]
    fn ext4_separate_single_disk_omits_persist_part() {
        let vdb = disk("vdb", 40 * GB, false);
        let vdc = disk("vdc", 40 * GB, false);
        let p = ready(plan(&vdb, &[vdc.clone()], Some("vda"), &InstallConfig::default(), &hw(8, "kvm")));
        assert_eq!(p.fs, Fs::Ext4);
        assert!(!p.make_raw_parts.contains(&"persist".to_string()));
        assert_eq!(p.persist, PersistPlan::Ext4 { device: PersistDevice::SeparateDisk("/dev/vdc".into()) });
    }

    #[test]
    fn multi_disk_forces_zfs_pool() {
        let vdb = disk("vdb", 40 * GB, false); // == install, so P3-on-install member + persist part
        let vdc = disk("vdc", 40 * GB, false);
        let p = ready(plan(&vdb, &[vdb.clone(), vdc.clone()], Some("vda"), &InstallConfig::default(), &hw(64, "kvm")));
        assert_eq!(p.fs, Fs::Zfs);
        assert!(p.make_raw_parts.contains(&"persist".to_string()));
        assert_eq!(
            p.persist,
            PersistPlan::Zfs {
                members: vec![PoolMember::P3OnInstallDisk, PoolMember::WholeDisk("/dev/vdc".into())],
                raid: RaidLevel::None,
                clustered: false,
            }
        );
    }

    #[test]
    fn multi_disk_pool_excluding_install_omits_persist_part() {
        let vdb = disk("vdb", 40 * GB, false); // install, not a persist member
        let vdc = disk("vdc", 40 * GB, false);
        let vdd = disk("vdd", 40 * GB, false);
        let p = ready(plan(&vdb, &[vdc.clone(), vdd.clone()], Some("vda"), &InstallConfig::default(), &hw(64, "kvm")));
        assert!(!p.make_raw_parts.contains(&"persist".to_string()));
        assert_eq!(
            p.persist,
            PersistPlan::Zfs {
                members: vec![PoolMember::WholeDisk("/dev/vdc".into()), PoolMember::WholeDisk("/dev/vdd".into())],
                raid: RaidLevel::None,
                clustered: false,
            }
        );
    }

    #[test]
    fn hv_k_zfs_is_clustered() {
        let vdb = disk("vdb", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.persist_fs = Some(Fs::Zfs);
        let p = ready(plan(&vdb, &[vdb.clone()], Some("vda"), &cfg, &hw(64, "k")));
        match p.persist {
            PersistPlan::Zfs { clustered, .. } => assert!(clustered),
            _ => panic!("expected zfs"),
        }
    }

    #[test]
    fn raid_level_recorded() {
        let vdb = disk("vdb", 40 * GB, false);
        let vdc = disk("vdc", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.zfs_raid_level = Some(RaidLevel::Raid1);
        let p = ready(plan(&vdb, &[vdb.clone(), vdc.clone()], Some("vda"), &cfg, &hw(64, "kvm")));
        match p.persist {
            PersistPlan::Zfs { raid, .. } => assert_eq!(raid, RaidLevel::Raid1),
            _ => panic!("expected zfs"),
        }
    }

    #[test]
    fn nuke_variants() {
        let vdb = disk("vdb", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.nuke_all_disks = Some(true);
        assert_eq!(ready(plan(&vdb, &[vdb.clone()], Some("vda"), &cfg, &hw(8, "kvm"))).nuke, NukePlan::AllDisks);
        let mut cfg2 = InstallConfig::default();
        cfg2.nuke_disks = Some(vec!["sde".into()]);
        assert_eq!(ready(plan(&vdb, &[vdb.clone()], Some("vda"), &cfg2, &hw(8, "kvm"))).nuke, NukePlan::Disks(vec!["sde".into()]));
        assert_eq!(ready(plan(&vdb, &[vdb.clone()], Some("vda"), &InstallConfig::default(), &hw(8, "kvm"))).nuke, NukePlan::None);
    }

    #[test]
    fn advisories_zfs_reqs_and_readonly_but_still_ready() {
        let vdb = disk("vdb", 40 * GB, true); // read-only
        let mut cfg = InstallConfig::default();
        cfg.persist_fs = Some(Fs::Zfs);
        let p = ready(plan(&vdb, &[vdb.clone()], Some("vda"), &cfg, &hw(8, "kvm"))); // 8GB RAM, 1 disk
        assert_eq!(p.fs, Fs::Zfs); // NOT downgraded
        assert!(p.advisories.iter().any(|a| a.contains("RAM") || a.contains("64")));
        assert!(p.advisories.iter().any(|a| a.contains("disks") || a.contains("3")));
        assert!(p.advisories.iter().any(|a| a.contains("read-only")));
    }

    #[test]
    fn skip_zfs_checks_suppresses_reqs_advisories() {
        let vdb = disk("vdb", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.persist_fs = Some(Fs::Zfs);
        cfg.skip_zfs_checks = Some(true);
        let p = ready(plan(&vdb, &[vdb.clone()], Some("vda"), &cfg, &hw(8, "kvm")));
        assert!(!p.advisories.iter().any(|a| a.contains("RAM") || a.contains("64")));
    }

    #[test]
    fn ext4_requested_for_multidisk_warns_and_uses_zfs() {
        let vdb = disk("vdb", 40 * GB, false);
        let vdc = disk("vdc", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.persist_fs = Some(Fs::Ext4);
        let p = ready(plan(&vdb, &[vdb.clone(), vdc.clone()], Some("vda"), &cfg, &hw(64, "kvm")));
        assert_eq!(p.fs, Fs::Zfs);
        assert!(p.advisories.iter().any(|a| a.contains("ext4")));
    }

    #[test]
    fn reject_install_or_persist_is_boot_disk() {
        let vda = disk("vda", 40 * GB, false);
        assert!(matches!(
            plan(&vda, &[vda.clone()], Some("vda"), &InstallConfig::default(), &hw(8, "kvm")),
            PlanOutcome::Rejected(_)
        ));
        let vdb = disk("vdb", 40 * GB, false);
        let vda2 = disk("vda", 40 * GB, false);
        assert!(matches!(
            plan(&vdb, &[vda2], Some("vda"), &InstallConfig::default(), &hw(8, "kvm")),
            PlanOutcome::Rejected(_)
        ));
    }

    #[test]
    fn reject_raid_needs_more_disks() {
        let vdb = disk("vdb", 40 * GB, false);
        let vdc = disk("vdc", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.zfs_raid_level = Some(RaidLevel::Raid5); // needs 3
        assert!(matches!(
            plan(&vdb, &[vdb.clone(), vdc.clone()], Some("vda"), &cfg, &hw(64, "kvm")),
            PlanOutcome::Rejected(_)
        ));
    }

    #[test]
    fn size_floor_is_placeholder_noop() {
        // A tiny disk is currently NOT rejected (placeholder). Pins the TODO.
        let tiny = disk("vdb", 4096, false);
        assert!(matches!(
            plan(&tiny, &[tiny.clone()], Some("vda"), &InstallConfig::default(), &hw(8, "kvm")),
            PlanOutcome::Ready(_)
        ));
    }

    #[test]
    fn advisory_readonly_persist_non_install() {
        let vdb = disk("vdb", 40 * GB, false); // install, not read-only
        let vdc = disk("vdc", 40 * GB, true); // persist member, read-only, not the install disk
        let p = ready(plan(&vdb, &[vdb.clone(), vdc.clone()], Some("vda"), &InstallConfig::default(), &hw(64, "kvm")));
        assert_eq!(p.fs, Fs::Zfs); // multi-disk -> zfs
        assert!(p.advisories.iter().any(|a| a.contains("vdc") && a.contains("read-only")));
    }

    #[test]
    fn single_disk_zfs_raid_level_alone_selects_zfs() {
        // SP-1 cmdline-vs-JSON asymmetry: zfs_raid_level set, persist_fs left unset.
        let vdb = disk("vdb", 40 * GB, false);
        let mut cfg = InstallConfig::default();
        cfg.zfs_raid_level = Some(RaidLevel::None); // None => raid_min_disks == 1, satisfied by single disk
        assert!(cfg.persist_fs.is_none());
        let p = ready(plan(&vdb, &[vdb.clone()], Some("vda"), &cfg, &hw(64, "kvm")));
        assert_eq!(p.fs, Fs::Zfs);
    }

    #[test]
    fn reject_empty_persist_list() {
        let vdb = disk("vdb", 40 * GB, false);
        assert!(matches!(
            plan(&vdb, &[], Some("vda"), &InstallConfig::default(), &hw(8, "kvm")),
            PlanOutcome::Rejected(_)
        ));
    }
}
