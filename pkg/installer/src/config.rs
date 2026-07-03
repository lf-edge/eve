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

/// Split a comma-separated value into non-empty trimmed parts; `None` if empty.
fn split_csv(s: &str) -> Option<Vec<String>> {
    let parts: Vec<String> = s
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts)
    }
}

/// `Some(owned)` if non-empty, else `None`.
fn nonempty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parse `eve_install_*` tokens from a kernel cmdline. Total: unknown `eve_*`
/// tokens produce an `UnknownToken` warning, non-`eve_` tokens are ignored,
/// and malformed values produce a `BadValue` warning while leaving the field
/// `None`. Never panics.
pub fn parse_cmdline(cmdline: &str) -> (InstallConfig, Vec<Warning>) {
    let mut cfg = InstallConfig::default();
    let mut warnings = Vec::new();

    for token in cmdline.split_whitespace() {
        let (key, value) = match token.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (token, None),
        };
        // non-empty value, if any
        let val = value.filter(|v| !v.is_empty());

        match key {
            // value-carrying flags
            "eve_install_disk" => cfg.install_disk = val.and_then(nonempty),
            "eve_persist_disk" => cfg.persist_disk = val.and_then(split_csv),
            "eve_install_server" => cfg.install_server = val.and_then(nonempty),
            "eve_soft_serial" => cfg.soft_serial = val.and_then(nonempty),
            "eve_nuke_disks" => cfg.nuke_disks = val.and_then(split_csv),
            "eve_install_zfs_with_raid_level" => {
                if let Some(v) = val {
                    match RaidLevel::from_cmdline(v) {
                        Some(r) => cfg.zfs_raid_level = Some(r),
                        None => warnings.push(Warning::BadValue {
                            token: key.to_string(),
                            value: v.to_string(),
                        }),
                    }
                }
            }
            "eve_install_k3s_etcd_sizeGB" => {
                if let Some(v) = val {
                    match v.parse::<u32>() {
                        Ok(n) => cfg.k3s_etcd_size_gb = Some(n),
                        Err(_) => warnings.push(Warning::BadValue {
                            token: key.to_string(),
                            value: v.to_string(),
                        }),
                    }
                }
            }
            // bare presence flags (any value ignored; presence => true)
            "eve_install_skip_config" => cfg.skip_config = Some(true),
            "eve_install_skip_persist" => cfg.skip_persist = Some(true),
            "eve_install_skip_rootfs" => cfg.skip_rootfs = Some(true),
            "eve_install_skip_zfs_checks" => cfg.skip_zfs_checks = Some(true),
            "eve_disable_verify" => cfg.disable_verify = Some(true),
            "eve_skip_dev_cert" => cfg.skip_dev_cert = Some(true),
            "eve_reboot_after_install" => cfg.reboot_after_install = Some(true),
            "eve_nuke_all_disks" => cfg.nuke_all_disks = Some(true),
            "eve_blackbox" => cfg.blackbox = Some(true),
            "eve_pause_before_install" => cfg.pause_before_install = Some(true),
            "eve_pause_after_install" => cfg.pause_after_install = Some(true),
            "eve_install_debug" => cfg.install_debug = Some(true),
            // unrecognized installer-ish token
            other if other.starts_with("eve_") => {
                warnings.push(Warning::UnknownToken(other.to_string()))
            }
            // ordinary kernel tokens: ignore silently
            _ => {}
        }
    }

    // persist_fs inference: a zfs raid level (even "none") implies the zfs filesystem
    if cfg.zfs_raid_level.is_some() && cfg.persist_fs.is_none() {
        cfg.persist_fs = Some(Fs::Zfs);
    }

    (cfg, warnings)
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

    #[test]
    fn cmdline_parses_value_and_bare_flags() {
        let (c, w) = parse_cmdline(
            "getty rootwait eve_install_disk=sda eve_install_server=zedcloud.example.com \
             eve_install_skip_persist eve_reboot_after_install",
        );
        assert_eq!(c.install_disk.as_deref(), Some("sda"));
        assert_eq!(c.install_server.as_deref(), Some("zedcloud.example.com"));
        assert_eq!(c.skip_persist, Some(true));
        assert_eq!(c.reboot_after_install, Some(true));
        assert!(w.is_empty());
    }

    #[test]
    fn cmdline_parses_comma_lists() {
        let (c, _) = parse_cmdline("eve_persist_disk=sdb,sdc,sdd eve_nuke_disks=sde");
        assert_eq!(
            c.persist_disk,
            Some(vec!["sdb".into(), "sdc".into(), "sdd".into()])
        );
        assert_eq!(c.nuke_disks, Some(vec!["sde".into()]));
    }

    #[test]
    fn cmdline_infers_zfs_fs_from_raid_level() {
        let (c, w) = parse_cmdline("eve_install_zfs_with_raid_level=raid1");
        assert_eq!(c.zfs_raid_level, Some(RaidLevel::Raid1));
        assert_eq!(c.persist_fs, Some(Fs::Zfs));
        assert!(w.is_empty());
    }

    #[test]
    fn cmdline_bad_values_warn_and_leave_none() {
        let (c, w) = parse_cmdline("eve_install_zfs_with_raid_level=raid9 eve_install_k3s_etcd_sizeGB=big");
        assert!(c.zfs_raid_level.is_none());
        assert!(c.k3s_etcd_size_gb.is_none());
        assert_eq!(w.len(), 2);
        assert!(w.contains(&Warning::BadValue {
            token: "eve_install_zfs_with_raid_level".into(),
            value: "raid9".into()
        }));
    }

    #[test]
    fn cmdline_unknown_eve_token_warns_but_others_ignored() {
        let (c, w) = parse_cmdline("console=ttyS0 eve_install_dsk=sda");
        assert!(c.install_disk.is_none());
        assert_eq!(w, vec![Warning::UnknownToken("eve_install_dsk".into())]);
    }

    #[test]
    fn cmdline_empty_values_become_none() {
        let (c, w) = parse_cmdline("eve_install_disk= eve_persist_disk=");
        assert!(c.install_disk.is_none());
        assert!(c.persist_disk.is_none());
        assert!(w.is_empty());
    }
}
