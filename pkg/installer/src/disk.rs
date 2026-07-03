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
}

// Raw lsblk -J -b -o NAME,TYPE,SIZE,TRAN,MODEL,SERIAL,RO entry.
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
            Some(Disk {
                path: format!("/dev/{name}"),
                kind: d.kind.unwrap_or_default(),
                size_bytes: d.size,
                transport: d.tran.as_deref().map(Transport::from_lsblk),
                model: d.model,
                serial: d.serial,
                read_only: d.ro.unwrap_or(false),
                virtual_dev: false,
                name,
            })
        })
        .collect();
    (disks, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LSBLK_VM: &str = r#"{"blockdevices":[
      {"name":"vda","type":"disk","size":21474836480,"tran":"virtio","model":null,"serial":null,"ro":false},
      {"name":"vdb","type":"disk","size":8589934592,"tran":"virtio","model":null,"serial":null,"ro":false},
      {"name":"sr0","type":"rom","size":1048576,"tran":"sata","model":"QEMU","serial":null,"ro":true},
      {"name":"loop0","type":"loop","size":1234,"tran":null,"model":null,"serial":null,"ro":true}
    ]}"#;

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
}
