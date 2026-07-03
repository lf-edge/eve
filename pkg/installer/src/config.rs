/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#![allow(dead_code)] // consumed by SP-2 (orchestration) and SP-3 (TUI); not wired into the binary yet.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Persist filesystem choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Fs {
    Ext4,
    Zfs,
}

/// ZFS RAID level for the persist pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RaidLevel {
    None,
    Raid1,
    Raid5,
    Raid6,
}

impl RaidLevel {
    /// Parse a cmdline raid-level value (`none|raid1|raid5|raid6`).
    fn from_cmdline(s: &str) -> Option<RaidLevel> {
        match s {
            "none" => Some(RaidLevel::None),
            "raid1" => Some(RaidLevel::Raid1),
            "raid5" => Some(RaidLevel::Raid5),
            "raid6" => Some(RaidLevel::Raid6),
            _ => None,
        }
    }
}

/// A non-fatal diagnostic collected during parsing. Callers may log these;
/// parsing never aborts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    UnknownToken(String),
    BadValue { token: String, value: String },
    BadJson(String),
}

/// The one source of truth for installer configuration. Every field is optional:
/// absent means "not specified at this layer", which makes `or` a clean merge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "snake_case")]
pub struct InstallConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_disk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persist_disk: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persist_fs: Option<Fs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zfs_raid_level: Option<RaidLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k3s_etcd_size_gb: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_config: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_persist: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_rootfs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_zfs_checks: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_dev_cert: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reboot_after_install: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nuke_disks: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nuke_all_disks: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blackbox: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_before_install: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_after_install: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_debug: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_all_none_and_serializes_empty() {
        let c = InstallConfig::default();
        assert!(c.install_disk.is_none());
        assert!(c.persist_disk.is_none());
        assert!(c.zfs_raid_level.is_none());
        // skip_serializing_if + serde(default) means an empty config is `{}`
        assert_eq!(serde_json::to_string(&c).unwrap(), "{}");
    }

    #[test]
    fn enums_serialize_lowercase() {
        assert_eq!(serde_json::to_string(&RaidLevel::Raid1).unwrap(), "\"raid1\"");
        assert_eq!(serde_json::to_string(&RaidLevel::None).unwrap(), "\"none\"");
        assert_eq!(serde_json::to_string(&Fs::Zfs).unwrap(), "\"zfs\"");
        assert_eq!(serde_json::to_string(&Fs::Ext4).unwrap(), "\"ext4\"");
    }
}
