/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#![allow(dead_code)] // consumed by SP-2b (orchestration) and SP-3 (TUI); not fully wired yet.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Transport {
    Nvme,
    Sata,
    Usb,
    Virtio,
    Other(String),
}

impl Transport {
    pub fn from_lsblk(s: &str) -> Transport {
        match s {
            "nvme" => Transport::Nvme,
            "sata" => Transport::Sata,
            "usb" => Transport::Usb,
            "virtio" => Transport::Virtio,
            other => Transport::Other(other.to_string()),
        }
    }
    /// Lower = preferred when auto-guessing the install target.
    pub fn priority(&self) -> u8 {
        match self {
            Transport::Nvme => 0,
            Transport::Sata => 1,
            Transport::Usb => 2,
            Transport::Virtio => 3,
            Transport::Other(_) => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Disk {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size_bytes: u64,
    pub transport: Option<Transport>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub read_only: bool,
    pub virtual_dev: bool,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Partition {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub fstype: Option<String>,
    pub label: Option<String>,
    pub partlabel: Option<String>,
}

// Raw lsblk -J -b -o NAME,TYPE,SIZE,TRAN,MODEL,SERIAL,RO,FSTYPE,LABEL,PARTLABEL entry.
#[derive(Deserialize)]
struct LsblkOut {
    blockdevices: Vec<LsblkDev>,
}
#[derive(Deserialize)]
struct LsblkDev {
    name: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    #[serde(default, deserialize_with = "de_flex_u64")]
    size: u64,
    #[serde(default)]
    tran: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    ro: Option<bool>,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    partlabel: Option<String>,
    #[serde(default)]
    children: Vec<LsblkDev>,
}

// Accept the byte count whether lsblk emits it as a JSON number or a string.
fn de_flex_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    use serde::Deserialize;
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::Number(n) => Ok(n.as_u64().unwrap_or(0)),
        serde_json::Value::String(s) => Ok(s.trim().parse::<u64>().unwrap_or(0)),
        _ => Ok(0),
    }
}

/// Parse `lsblk -J -b -o NAME,TYPE,SIZE,TRAN,MODEL,SERIAL,RO` output into typed
/// disks. Total: on any parse error return an empty list plus a warning.
/// `virtual_dev` is left false here; the I/O wrapper fills it.
pub fn parse_lsblk(json: &str) -> (Vec<Disk>, Vec<String>) {
    let parsed: LsblkOut = match serde_json::from_str(json) {
        Ok(p) => p,
        Err(e) => return (Vec::new(), vec![format!("lsblk parse failed: {e}")]),
    };
    let disks = parsed
        .blockdevices
        .into_iter()
        .filter_map(|d| {
            let name = d.name?;
            let partitions = d
                .children
                .into_iter()
                .filter_map(|c| {
                    let cname = c.name?;
                    Some(Partition {
                        path: format!("/dev/{cname}"),
                        size_bytes: c.size,
                        fstype: c.fstype,
                        label: c.label,
                        partlabel: c.partlabel,
                        name: cname,
                    })
                })
                .collect();
            Some(Disk {
                path: format!("/dev/{name}"),
                kind: d.kind.unwrap_or_default(),
                size_bytes: d.size,
                transport: d.tran.as_deref().map(Transport::from_lsblk),
                model: d.model,
                serial: d.serial,
                read_only: d.ro.unwrap_or(false),
                virtual_dev: false,
                partitions,
                name,
            })
        })
        .collect();
    (disks, Vec::new())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DiskResolution {
    Resolved {
        install: Disk,
        persist: Vec<Disk>,
        warnings: Vec<String>,
    },
    NeedInteractive(String),
}

// Match a disk by bare name ("vdb") or full path ("/dev/vdb").
fn find<'a>(disks: &'a [Disk], id: &str) -> Option<&'a Disk> {
    let bare = id.strip_prefix("/dev/").unwrap_or(id);
    disks.iter().find(|d| d.name == bare)
}

/// Resolve the install target + persist disk(s) from config and discovered disks.
/// Returns NeedInteractive (drop to TUI) when no usable target can be determined.
pub fn resolve(cfg: &crate::config::InstallConfig, disks: &[Disk], boot: Option<&str>) -> DiskResolution {
    let mut warnings = Vec::new();

    // Candidate = real disk, nonzero size, not virtual, not the boot disk.
    let boot_bare = boot.map(|b| b.strip_prefix("/dev/").unwrap_or(b));
    let mut candidates: Vec<&Disk> = disks
        .iter()
        .filter(|d| d.kind == "disk" && d.size_bytes > 0 && !d.virtual_dev)
        .filter(|d| Some(d.name.as_str()) != boot_bare)
        .collect();

    // Install target.
    let install: Disk = match cfg.install_disk.as_deref() {
        Some(id) => match find(disks, id) {
            Some(d) => d.clone(),
            None => return DiskResolution::NeedInteractive(format!("install disk {id} not found")),
        },
        None => {
            // stable order: transport priority, then name
            candidates.sort_by(|a, b| {
                let pa = a.transport.as_ref().map(|t| t.priority()).unwrap_or(u8::MAX);
                let pb = b.transport.as_ref().map(|t| t.priority()).unwrap_or(u8::MAX);
                pa.cmp(&pb).then(a.name.cmp(&b.name))
            });
            match candidates.first() {
                Some(d) => {
                    if candidates.len() > 1 {
                        let names: Vec<&str> = candidates.iter().map(|c| c.name.as_str()).collect();
                        warnings.push(format!(
                            "multiple free disks ({}), using {}",
                            names.join(", "),
                            d.name
                        ));
                    }
                    (*d).clone()
                }
                None => return DiskResolution::NeedInteractive("no free disk found".to_string()),
            }
        }
    };

    if install.read_only {
        warnings.push(format!("install disk {} is read-only", install.name));
    }

    // Persist disk(s). An explicit empty list (possible via JSON config) is
    // treated the same as unset: default to the install disk.
    let persist: Vec<Disk> = match cfg.persist_disk.as_ref() {
        Some(ids) if !ids.is_empty() => {
            let mut out = Vec::new();
            for id in ids {
                match find(disks, id) {
                    Some(d) => out.push(d.clone()),
                    None => {
                        return DiskResolution::NeedInteractive(format!("persist disk {id} not found"))
                    }
                }
            }
            out
        }
        _ => vec![install.clone()],
    };

    DiskResolution::Resolved { install, persist, warnings }
}

use std::path::Path;
use std::process::Command;

/// True if /sys/devices/virtual/block/<name> exists (loop/dm/etc.).
pub fn is_virtual(name: &str) -> bool {
    Path::new(&format!("/sys/devices/virtual/block/{name}")).exists()
}

// Given a "major:minor" string, return the base disk name from /sys/block, if any.
fn disk_for_devnum(devnum: &str) -> Option<String> {
    let block = Path::new("/sys/block");
    let entries = std::fs::read_dir(block).ok()?;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // whole-disk dev
        if let Ok(s) = std::fs::read_to_string(block.join(&name).join("dev")) {
            if s.trim() == devnum {
                return Some(name);
            }
        }
        // partition dev (e.g. /sys/block/sda/sda1/dev)
        if let Ok(sub) = std::fs::read_dir(block.join(&name)) {
            for p in sub.flatten() {
                let pn = p.file_name().to_string_lossy().to_string();
                if let Ok(s) = std::fs::read_to_string(block.join(&name).join(&pn).join("dev")) {
                    if s.trim() == devnum {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

// Decode a glibc-encoded dev_t into "major:minor" (see makedev(3)/gnu_dev_major).
fn devnum(dev: u64) -> String {
    let major = (dev >> 8) & 0xfff;
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    format!("{major}:{minor}")
}

/// Determine the disk the installer booted from (to exclude it as a target).
/// Order: EVE_INSTALL_BOOT_DISK override -> /dev/root -> device backing /bits.
pub fn detect_boot_disk() -> Option<String> {
    if let Ok(v) = std::env::var("EVE_INSTALL_BOOT_DISK") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.strip_prefix("/dev/").unwrap_or(v).to_string());
        }
    }
    // /dev/root -> real device -> major:minor
    if let Ok(meta) = std::fs::metadata("/dev/root") {
        use std::os::unix::fs::MetadataExt;
        if let Some(d) = disk_for_devnum(&devnum(meta.rdev())) {
            return Some(d);
        }
    }
    // fallback: the device that /bits lives on
    if let Ok(meta) = std::fs::metadata("/bits") {
        use std::os::unix::fs::MetadataExt;
        if let Some(d) = disk_for_devnum(&devnum(meta.dev())) {
            return Some(d);
        }
    }
    None
}

/// Run lsblk, parse, fill virtual_dev, and detect the boot disk. The only I/O
/// entry point; everything else in this module is pure.
pub fn discover() -> (Vec<Disk>, Option<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let out = Command::new("lsblk")
        .args(["-J", "-b", "-o", "NAME,TYPE,SIZE,TRAN,MODEL,SERIAL,RO,FSTYPE,LABEL,PARTLABEL"])
        .output();
    let json = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
        Ok(o) => {
            warnings.push(format!("lsblk failed: {}", String::from_utf8_lossy(&o.stderr).trim()));
            String::new()
        }
        Err(e) => {
            warnings.push(format!("lsblk not runnable: {e}"));
            String::new()
        }
    };
    let mut disks = Vec::new();
    if !json.is_empty() {
        let (d, mut w) = parse_lsblk(&json);
        disks = d;
        warnings.append(&mut w);
    }
    for d in &mut disks {
        d.virtual_dev = is_virtual(&d.name);
    }
    let boot = detect_boot_disk();
    (disks, boot, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InstallConfig;

    const LSBLK_VM: &str = r#"{"blockdevices":[
      {"name":"vda","type":"disk","size":21474836480,"tran":"virtio","model":null,"serial":null,"ro":false},
      {"name":"vdb","type":"disk","size":8589934592,"tran":"virtio","model":null,"serial":null,"ro":false},
      {"name":"sr0","type":"rom","size":1048576,"tran":"sata","model":"QEMU","serial":null,"ro":true},
      {"name":"loop0","type":"loop","size":1234,"tran":null,"model":null,"serial":null,"ro":true}
    ]}"#;

    fn disk(name: &str, kind: &str, size: u64, tran: Transport, virt: bool) -> Disk {
        Disk {
            name: name.to_string(),
            path: format!("/dev/{name}"),
            kind: kind.to_string(),
            size_bytes: size,
            transport: Some(tran),
            model: None,
            serial: None,
            read_only: false,
            virtual_dev: virt,
            partitions: vec![],
        }
    }

    #[test]
    fn parse_lsblk_maps_fields_and_types() {
        let (disks, w) = parse_lsblk(LSBLK_VM);
        assert!(w.is_empty());
        assert_eq!(disks.len(), 4);
        let vdb = disks.iter().find(|d| d.name == "vdb").unwrap();
        assert_eq!(vdb.path, "/dev/vdb");
        assert_eq!(vdb.kind, "disk");
        assert_eq!(vdb.size_bytes, 8589934592);
        assert_eq!(vdb.transport, Some(Transport::Virtio));
        assert!(!vdb.read_only);
        let sr0 = disks.iter().find(|d| d.name == "sr0").unwrap();
        assert!(sr0.read_only);
        assert_eq!(sr0.kind, "rom");
    }

    #[test]
    fn parse_lsblk_accepts_string_size() {
        // some lsblk versions quote the byte count even with -b
        let (disks, w) = parse_lsblk(r#"{"blockdevices":[{"name":"sda","type":"disk","size":"500107862016","tran":"sata"}]}"#);
        assert!(w.is_empty());
        assert_eq!(disks[0].size_bytes, 500107862016);
        assert_eq!(disks[0].transport, Some(Transport::Sata));
    }

    #[test]
    fn parse_lsblk_garbage_is_empty_with_warning() {
        let (disks, w) = parse_lsblk("not json");
        assert!(disks.is_empty());
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn transport_priority_order() {
        assert!(Transport::Nvme.priority() < Transport::Sata.priority());
        assert!(Transport::Sata.priority() < Transport::Usb.priority());
        assert!(Transport::Usb.priority() < Transport::Virtio.priority());
        assert!(Transport::Virtio.priority() < Transport::Other("x".into()).priority());
    }

    #[test]
    fn resolve_excludes_boot_virtual_nondisk_and_zero_size() {
        let disks = vec![
            disk("vda", "disk", 20, Transport::Virtio, false), // boot
            disk("vdb", "disk", 8, Transport::Virtio, false),  // candidate
            disk("sr0", "rom", 1, Transport::Sata, false),     // not disk
            disk("loop0", "loop", 1, Transport::Other("".into()), true), // virtual+loop
            disk("vdz", "disk", 0, Transport::Virtio, false),  // zero size
        ];
        let r = resolve(&InstallConfig::default(), &disks, Some("vda"));
        match r {
            DiskResolution::Resolved { install, persist, .. } => {
                assert_eq!(install.name, "vdb");
                assert_eq!(persist.len(), 1);
                assert_eq!(persist[0].name, "vdb"); // persist defaults to install
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_autoguess_prefers_transport_priority_and_warns_on_multiple() {
        let disks = vec![
            disk("sdb", "disk", 8, Transport::Usb, false),
            disk("nvme0n1", "disk", 8, Transport::Nvme, false),
            disk("sda", "disk", 8, Transport::Sata, false),
        ];
        let r = resolve(&InstallConfig::default(), &disks, None);
        match r {
            DiskResolution::Resolved { install, warnings, .. } => {
                assert_eq!(install.name, "nvme0n1"); // nvme wins
                assert!(warnings.iter().any(|w| w.contains("multiple")));
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_no_candidate_needs_interactive() {
        let disks = vec![disk("vda", "disk", 20, Transport::Virtio, false)];
        assert!(matches!(
            resolve(&InstallConfig::default(), &disks, Some("vda")),
            DiskResolution::NeedInteractive(_)
        ));
    }

    #[test]
    fn resolve_named_install_disk_found_and_missing() {
        let disks = vec![
            disk("vdb", "disk", 8, Transport::Virtio, false),
            disk("vdc", "disk", 8, Transport::Virtio, false),
        ];
        let mut cfg = InstallConfig::default();
        cfg.install_disk = Some("vdc".into());
        match resolve(&cfg, &disks, None) {
            DiskResolution::Resolved { install, .. } => assert_eq!(install.name, "vdc"),
            _ => panic!("expected Resolved"),
        }
        cfg.install_disk = Some("nope".into());
        assert!(matches!(resolve(&cfg, &disks, None), DiskResolution::NeedInteractive(_)));
    }

    #[test]
    fn resolve_persist_list_and_missing() {
        let disks = vec![
            disk("vdb", "disk", 8, Transport::Virtio, false),
            disk("vdc", "disk", 8, Transport::Virtio, false),
        ];
        let mut cfg = InstallConfig::default();
        cfg.install_disk = Some("vdb".into());
        cfg.persist_disk = Some(vec!["vdc".into()]);
        match resolve(&cfg, &disks, None) {
            DiskResolution::Resolved { persist, .. } => {
                assert_eq!(persist.len(), 1);
                assert_eq!(persist[0].name, "vdc");
            }
            _ => panic!("expected Resolved"),
        }
        cfg.persist_disk = Some(vec!["ghost".into()]);
        assert!(matches!(resolve(&cfg, &disks, None), DiskResolution::NeedInteractive(_)));
    }

    #[test]
    fn resolve_persist_multi_element() {
        let disks = vec![
            disk("vdb", "disk", 8, Transport::Virtio, false),
            disk("vdc", "disk", 8, Transport::Virtio, false),
        ];
        let mut cfg = InstallConfig::default();
        cfg.install_disk = Some("vdb".into());
        cfg.persist_disk = Some(vec!["vdb".into(), "vdc".into()]);
        match resolve(&cfg, &disks, None) {
            DiskResolution::Resolved { persist, .. } => {
                assert_eq!(persist.len(), 2);
                assert_eq!(persist[0].name, "vdb");
                assert_eq!(persist[1].name, "vdc");
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_empty_persist_list_defaults_to_install() {
        let disks = vec![
            disk("vdb", "disk", 8, Transport::Virtio, false),
            disk("vdc", "disk", 8, Transport::Virtio, false),
        ];
        let mut cfg = InstallConfig::default();
        cfg.install_disk = Some("vdb".into());
        cfg.persist_disk = Some(vec![]); // only reachable via JSON config
        match resolve(&cfg, &disks, None) {
            DiskResolution::Resolved { persist, .. } => {
                assert_eq!(persist.len(), 1);
                assert_eq!(persist[0].name, "vdb");
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_readonly_target_warns() {
        let disks = vec![Disk {
            name: "vdb".to_string(),
            path: "/dev/vdb".to_string(),
            kind: "disk".to_string(),
            size_bytes: 8,
            transport: Some(Transport::Virtio),
            model: None,
            serial: None,
            read_only: true,
            virtual_dev: false,
            partitions: vec![],
        }];
        match resolve(&InstallConfig::default(), &disks, None) {
            DiskResolution::Resolved { install, warnings, .. } => {
                assert_eq!(install.name, "vdb");
                assert!(warnings.iter().any(|w| w.contains("read-only")));
            }
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn resolve_autoguess_orders_virtio_before_other() {
        let disks = vec![
            disk("mmcblk0", "disk", 8, Transport::Other("mmc".into()), false),
            disk("vdb", "disk", 8, Transport::Virtio, false),
        ];
        match resolve(&InstallConfig::default(), &disks, None) {
            DiskResolution::Resolved { install, .. } => assert_eq!(install.name, "vdb"),
            _ => panic!("expected Resolved"),
        }
    }

    #[test]
    fn detect_boot_disk_honors_env_override() {
        // SAFETY: single-threaded test; set + remove within the test.
        std::env::set_var("EVE_INSTALL_BOOT_DISK", "/dev/vda");
        assert_eq!(detect_boot_disk().as_deref(), Some("vda"));
        std::env::remove_var("EVE_INSTALL_BOOT_DISK");
    }

    #[test]
    fn devnum_glibc_decode() {
        // major=8, minor=257 (minor >= 256 would truncate under the old 16-bit decode).
        let encoded: u64 = ((8 & 0xfff) << 8) | (257 & 0xff) | ((257 & !0xff) << 12);
        assert_eq!(encoded, 1050625);
        assert_eq!(devnum(encoded), "8:257");
        // small case: major=8, minor=1.
        let encoded_small: u64 = ((8 & 0xfff) << 8) | (1 & 0xff) | ((1 & !0xff) << 12);
        assert_eq!(encoded_small, 2049);
        assert_eq!(devnum(encoded_small), "8:1");
    }

    #[test]
    fn is_virtual_is_total() {
        // Must not panic regardless of host; a clearly-absent device is not virtual.
        assert!(!is_virtual("definitely-not-a-real-device-xyz"));
    }

    #[test]
    fn discover_does_not_panic() {
        // Smoke: on any host this returns without panicking (contents are host-dependent).
        let (_disks, _boot, _w) = discover();
    }

    #[test]
    fn parse_lsblk_captures_partitions() {
        let json = r#"{"blockdevices":[
          {"name":"vda","type":"disk","size":40000000000,"tran":"virtio","ro":false,
           "children":[
             {"name":"vda1","type":"part","size":2000000000,"fstype":"vfat","label":"EFI","partlabel":"EFI System"},
             {"name":"vda2","type":"part","size":38000000000,"fstype":"ext4","label":"root","partlabel":"P3"}
           ]},
          {"name":"vdb","type":"disk","size":8000000000,"tran":"virtio","ro":false}
        ]}"#;
        let (disks, w) = parse_lsblk(json);
        assert!(w.is_empty());
        let vda = disks.iter().find(|d| d.name == "vda").unwrap();
        assert_eq!(vda.partitions.len(), 2);
        assert_eq!(vda.partitions[0].name, "vda1");
        assert_eq!(vda.partitions[0].path, "/dev/vda1");
        assert_eq!(vda.partitions[0].fstype.as_deref(), Some("vfat"));
        assert_eq!(vda.partitions[0].partlabel.as_deref(), Some("EFI System"));
        assert_eq!(vda.partitions[1].fstype.as_deref(), Some("ext4"));
        let vdb = disks.iter().find(|d| d.name == "vdb").unwrap();
        assert!(vdb.partitions.is_empty());
    }
}
