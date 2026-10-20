/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#![allow(dead_code)] // real Execute path is exercised on an appliance; dry-run here.

use anyhow::{bail, Context, Result};

use crate::disk::Disk;
use crate::plan::{InstallPlan, NukePlan, PersistDevice, PersistPlan};

const P3_TYPE: &str = "5f24425a-2dfa-11e8-a270-7b663faccc2c";
const PERSIST_UUID: &str = "ad6871ee-31f9-4cf3-9e09-6f7a25c30059";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Execute,
    DryRun,
}

/// Runs external commands (or logs them in DryRun). Every command flows through
/// here so DryRun captures the full action sequence.
struct Runner {
    mode: Mode,
    log: Vec<String>,
}

impl Runner {
    fn new(mode: Mode) -> Self {
        Runner { mode, log: Vec::new() }
    }

    /// Record a non-fatal warning in the action log (e.g. best-effort nuke failures).
    fn warn(&mut self, msg: String) {
        self.log.push(msg);
    }

    fn cmd(&mut self, program: &str, args: &[&str]) -> Result<()> {
        self.log.push(format!("{} {}", program, args.join(" ")));
        match self.mode {
            Mode::DryRun => Ok(()),
            Mode::Execute => {
                let status = std::process::Command::new(program)
                    .args(args)
                    .status()
                    .with_context(|| format!("failed to spawn {program}"))?;
                if !status.success() {
                    bail!("{program} {} exited with {status}", args.join(" "));
                }
                Ok(())
            }
        }
    }

    /// Resolve the P3 partition device on `disk`. Symbolic in DryRun.
    fn find_p3(&mut self, disk_name: &str) -> Result<String> {
        match self.mode {
            Mode::DryRun => Ok(format!("/dev/{disk_name}:P3")),
            Mode::Execute => {
                let out = std::process::Command::new("lsblk")
                    .args(["-nro", "NAME,PARTLABEL", &format!("/dev/{disk_name}")])
                    .output()
                    .context("lsblk to find P3")?;
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let mut it = line.split_whitespace();
                    let name = it.next().unwrap_or("");
                    let label = it.next().unwrap_or("");
                    if label == "P3" {
                        return Ok(format!("/dev/{name}"));
                    }
                }
                bail!("P3 partition not found on /dev/{disk_name}")
            }
        }
    }

    /// Seek offset (in 512b sectors) for the tail-zeroing dd = device_size - 10240.
    /// A concrete number in Execute; a symbolic token in DryRun.
    fn tail_seek(&mut self, dev: &str) -> Result<String> {
        match self.mode {
            Mode::DryRun => Ok("<SIZE_SECTORS_MINUS_10240>".to_string()),
            Mode::Execute => {
                let out = std::process::Command::new("blockdev")
                    .args(["--getsz", dev])
                    .output()
                    .context("blockdev --getsz")?;
                let sectors: u64 = String::from_utf8_lossy(&out.stdout)
                    .trim()
                    .parse()
                    .context("parsing blockdev --getsz output")?;
                Ok(sectors.saturating_sub(10240).to_string())
            }
        }
    }
}

fn nuke_disk(r: &mut Runner, name: &str) -> Result<()> {
    r.cmd("dd", &["if=/dev/zero", &format!("of=/dev/{name}"), "bs=512", "count=34"])
}

fn create_separate_p3(r: &mut Runner, dev: &str) -> Result<()> {
    r.cmd("dd", &["if=/dev/zero", &format!("of={dev}"), "bs=512", "count=1", "conv=notrunc"])?;
    r.cmd("sgdisk", &["-Z", "--clear", dev])?;
    r.cmd("sgdisk", &["--new", "1:2048:0", &format!("--typecode=1:{P3_TYPE}"), "--change-name=1:P3", dev])?;
    r.cmd("sgdisk", &[&format!("--partition-guid=1:{PERSIST_UUID}"), dev])
}

fn make_ext4_persist(r: &mut Runner, p3: &str) -> Result<()> {
    // zero the first and last 5 MiB (10240 * 512b sectors) of residual data
    r.cmd("dd", &["if=/dev/zero", &format!("of={p3}"), "bs=512", "count=10240"])?;
    let seek = r.tail_seek(p3)?;
    r.cmd("dd", &["if=/dev/zero", &format!("of={p3}"), "bs=512", &format!("seek={seek}"), "count=10240"])?;
    r.cmd("mkfs.ext4", &["-F", "-F", "-O", "encrypt", p3])?;
    r.cmd("mkdir", &["-p", "/persist"])?;
    r.cmd("mount", &[p3, "/persist"])
}

/// Execute (or, in DryRun, log) the ext4 install plan. Returns the action log.
/// A ZFS plan is refused before any destructive step.
pub fn run(
    plan: &InstallPlan,
    install: &Disk,
    persist: &[Disk],
    all_disks: &[Disk],
    mode: Mode,
) -> Result<Vec<String>> {
    if let PersistPlan::Zfs { .. } = plan.persist {
        bail!("zfs execution not yet implemented (SP-2c-zfs)");
    }
    let mut r = Runner::new(mode);

    // 1. nuke
    match &plan.nuke {
        NukePlan::None => {}
        NukePlan::Disks(list) => {
            for d in list {
                nuke_disk(&mut r, d)?;
            }
        }
        NukePlan::AllDisks => {
            // Mirror the shell installer's nuke-all (install:305-310): only real,
            // non-empty, non-virtual disks, and best-effort (a single failing
            // device must not abort the whole install).
            for d in all_disks {
                if d.kind != "disk" || d.size_bytes == 0 || d.virtual_dev {
                    continue;
                }
                if let Err(e) = nuke_disk(&mut r, &d.name) {
                    r.warn(format!("warning: nuke of {} failed: {e}", d.name));
                }
            }
        }
    }

    // 2. make-raw
    let make_raw = std::env::var("EVE_MAKE_RAW").unwrap_or_else(|_| "/mkimage/make-raw".to_string());
    let mut mr_args: Vec<&str> = vec![install.path.as_str()];
    for p in &plan.make_raw_parts {
        mr_args.push(p.as_str());
    }
    r.cmd(&make_raw, &mr_args)?;

    // 3 + 4. persist (ext4 only; zfs already refused)
    let PersistPlan::Ext4 { device } = &plan.persist else {
        unreachable!("zfs refused above");
    };
    let p3 = match device {
        PersistDevice::P3OnInstallDisk => {
            // Re-read the partition table before looking up P3, so a stale
            // kernel view (from the make-raw write above) doesn't cause a
            // spurious "P3 partition not found".
            r.cmd("partprobe", &[install.path.as_str()])?;
            r.find_p3(&install.name)?
        }
        PersistDevice::SeparateDisk(dev) => {
            create_separate_p3(&mut r, dev)?;
            r.cmd("partprobe", &[dev.as_str()])?;
            r.find_p3(dev.strip_prefix("/dev/").unwrap_or(dev))?
        }
    };
    let _ = persist; // resolved persist disks are reflected in the plan's PersistPlan
    make_ext4_persist(&mut r, &p3)?;

    Ok(r.log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Fs, RaidLevel};

    fn disk(name: &str) -> Disk {
        disk_ex(name, "disk", 40 * 1024 * 1024 * 1024, false)
    }

    fn disk_ex(name: &str, kind: &str, size_bytes: u64, virtual_dev: bool) -> Disk {
        Disk {
            name: name.to_string(),
            path: format!("/dev/{name}"),
            kind: kind.to_string(),
            size_bytes,
            transport: None,
            model: None,
            serial: None,
            read_only: false,
            virtual_dev,
            partitions: vec![],
        }
    }
    fn base_plan(persist: PersistPlan, parts: &[&str], nuke: NukePlan) -> InstallPlan {
        InstallPlan {
            fs: Fs::Ext4,
            make_raw_parts: parts.iter().map(|s| s.to_string()).collect(),
            persist,
            nuke,
            advisories: vec![],
        }
    }
    fn joined(log: &[String]) -> String { log.join("\n") }

    #[test]
    fn dryrun_ext4_persist_on_install() {
        let vdb = disk("vdb");
        let plan = base_plan(
            PersistPlan::Ext4 { device: PersistDevice::P3OnInstallDisk },
            &["efi", "efi_b", "imga", "imgb", "conf", "persist"],
            NukePlan::None,
        );
        let log = run(&plan, &vdb, &[vdb.clone()], &[vdb.clone()], Mode::DryRun).unwrap();
        let s = joined(&log);
        assert!(s.contains("make-raw /dev/vdb efi efi_b imga imgb conf persist"));
        assert!(s.contains("mkfs.ext4"));
        assert!(s.contains("mount"));
        assert!(s.contains("/persist"));
        // no separate-disk P3 creation when P3 is on the install disk
        assert!(!s.contains("sgdisk --new"));
    }

    #[test]
    fn dryrun_ext4_separate_disk_creates_p3_and_omits_persist_part() {
        let vdb = disk("vdb");
        let vdc = disk("vdc");
        let plan = base_plan(
            PersistPlan::Ext4 { device: PersistDevice::SeparateDisk("/dev/vdc".into()) },
            &["efi", "efi_b", "imga", "imgb", "conf"],
            NukePlan::None,
        );
        let log = run(&plan, &vdb, &[vdc.clone()], &[vdb.clone(), vdc.clone()], Mode::DryRun).unwrap();
        let s = joined(&log);
        assert!(s.contains("make-raw /dev/vdb efi efi_b imga imgb conf"));
        assert!(!s.contains("conf persist"));
        assert!(s.contains("sgdisk --new")); // P3 created on the separate disk
        assert!(s.contains("/dev/vdc"));
        assert!(s.contains("mkfs.ext4"));
    }

    #[test]
    fn dryrun_nuke_variants() {
        let vdb = disk("vdb");
        let plan_list = base_plan(
            PersistPlan::Ext4 { device: PersistDevice::P3OnInstallDisk },
            &["efi"],
            NukePlan::Disks(vec!["sde".into()]),
        );
        let s = joined(&run(&plan_list, &vdb, &[vdb.clone()], &[vdb.clone()], Mode::DryRun).unwrap());
        assert!(s.contains("dd") && s.contains("of=/dev/sde"));

        let vdc = disk("vdc");
        let plan_all = base_plan(
            PersistPlan::Ext4 { device: PersistDevice::P3OnInstallDisk },
            &["efi"],
            NukePlan::AllDisks,
        );
        let s2 = joined(&run(&plan_all, &vdb, &[vdb.clone()], &[vdb.clone(), vdc.clone()], Mode::DryRun).unwrap());
        assert!(s2.contains("of=/dev/vdb") && s2.contains("of=/dev/vdc"));
    }

    #[test]
    fn dryrun_nuke_all_skips_non_disk_and_zero_size() {
        let real = disk_ex("vdb", "disk", 40 * 1024 * 1024 * 1024, false);
        let rom = disk_ex("sr0", "rom", 1024 * 1024 * 1024, false);
        let zero = disk_ex("vdc", "disk", 0, false);
        let virt = disk_ex("vdd", "disk", 40 * 1024 * 1024 * 1024, true);
        let plan = base_plan(
            PersistPlan::Ext4 { device: PersistDevice::P3OnInstallDisk },
            &["efi"],
            NukePlan::AllDisks,
        );
        let all = [real.clone(), rom, zero, virt];
        let log = run(&plan, &real, &[real.clone()], &all, Mode::DryRun).unwrap();
        let s = joined(&log);
        assert!(s.contains("dd") && s.contains("of=/dev/vdb"));
        assert!(!s.contains("of=/dev/sr0"));
        assert!(!s.contains("of=/dev/vdc"));
        assert!(!s.contains("of=/dev/vdd"));
    }

    #[test]
    fn zfs_plan_refused_before_any_action() {
        let vdb = disk("vdb");
        let plan = base_plan(
            PersistPlan::Zfs { members: vec![], raid: RaidLevel::None, clustered: false },
            &["efi"],
            NukePlan::Disks(vec!["sde".into()]),
        );
        let err = run(&plan, &vdb, &[vdb.clone()], &[vdb.clone()], Mode::DryRun).unwrap_err();
        assert!(err.to_string().contains("not yet implemented"));
    }
}
