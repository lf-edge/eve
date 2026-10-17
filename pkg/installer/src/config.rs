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

/// Parse an `unattended.json` document into a partial `InstallConfig`.
/// Tolerant: unknown keys are ignored; any deserialize error degrades to an
/// empty config plus a `BadJson` warning (we never pre-validate/abort).
pub fn parse_json(text: &str) -> (InstallConfig, Vec<Warning>) {
    match serde_json::from_str::<InstallConfig>(text) {
        Ok(cfg) => (cfg, Vec::new()),
        Err(e) => (InstallConfig::default(), vec![Warning::BadJson(e.to_string())]),
    }
}

impl InstallConfig {
    /// Field-wise merge. `self` is the higher-precedence layer: for each field,
    /// keep `self`'s value if present, otherwise take `lower`'s.
    pub fn or(self, lower: InstallConfig) -> InstallConfig {
        InstallConfig {
            install_disk: self.install_disk.or(lower.install_disk),
            persist_disk: self.persist_disk.or(lower.persist_disk),
            install_server: self.install_server.or(lower.install_server),
            soft_serial: self.soft_serial.or(lower.soft_serial),
            persist_fs: self.persist_fs.or(lower.persist_fs),
            zfs_raid_level: self.zfs_raid_level.or(lower.zfs_raid_level),
            k3s_etcd_size_gb: self.k3s_etcd_size_gb.or(lower.k3s_etcd_size_gb),
            skip_config: self.skip_config.or(lower.skip_config),
            skip_persist: self.skip_persist.or(lower.skip_persist),
            skip_rootfs: self.skip_rootfs.or(lower.skip_rootfs),
            skip_zfs_checks: self.skip_zfs_checks.or(lower.skip_zfs_checks),
            disable_verify: self.disable_verify.or(lower.disable_verify),
            skip_dev_cert: self.skip_dev_cert.or(lower.skip_dev_cert),
            reboot_after_install: self.reboot_after_install.or(lower.reboot_after_install),
            nuke_disks: self.nuke_disks.or(lower.nuke_disks),
            nuke_all_disks: self.nuke_all_disks.or(lower.nuke_all_disks),
            blackbox: self.blackbox.or(lower.blackbox),
            pause_before_install: self.pause_before_install.or(lower.pause_before_install),
            pause_after_install: self.pause_after_install.or(lower.pause_after_install),
            install_debug: self.install_debug.or(lower.install_debug),
        }
    }

    /// Serialize this config for save-back/cloning to another node, stripping
    /// fields that must not be cloned: `soft_serial` (per-device identity) and
    /// the diagnostic/pause flags. `skip_serializing_if` keeps absent fields out.
    pub fn to_unattended(&self) -> String {
        let mut clone = self.clone();
        clone.soft_serial = None;
        clone.pause_before_install = None;
        clone.pause_after_install = None;
        clone.install_debug = None;
        serde_json::to_string_pretty(&clone).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Resolve the effective config for the unattended path: read the first
/// existing candidate file (INVENTORY then /config, by convention), parse it,
/// and merge it over the cmdline (`json ▷ cmdline`). Absent/unreadable files
/// are skipped; the first file that exists "wins" even if it parses empty.
/// The only I/O performed by this module.
///
/// Note on `persist_fs` inference asymmetry: `parse_cmdline` infers
/// `persist_fs = Some(Fs::Zfs)` when a `zfs_raid_level` is present on the
/// cmdline, but `parse_json` performs no such inference, and this function
/// does not re-derive `persist_fs` after merging json over cmdline. So an
/// `unattended.json` that sets `zfs_raid_level` without also setting
/// `persist_fs` will yield `persist_fs: None` in the merged config even
/// though `zfs_raid_level` is `Some(_)`. This is per spec (JSON must state
/// `persist_fs` explicitly); SP-2 consumers must decide how to treat that
/// combination (e.g. treat a set `zfs_raid_level` as implying zfs even when
/// `persist_fs` is `None`, or treat it as a config error).
pub fn load(json_candidates: &[&Path], cmdline: &str) -> (InstallConfig, Vec<Warning>) {
    let (cmd_cfg, mut warnings) = parse_cmdline(cmdline);

    let mut json_cfg = InstallConfig::default();
    for path in json_candidates {
        match fs::read_to_string(path) {
            Ok(text) => {
                let (cfg, mut w) = parse_json(&text);
                warnings.append(&mut w);
                json_cfg = cfg;
                break; // first existing file wins
            }
            Err(_) => continue, // absent/unreadable: try the next candidate
        }
    }

    (json_cfg.or(cmd_cfg), warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        use std::io::Write;
        let mut p = std::env::temp_dir();
        p.push(format!("sp1_cfg_{}_{}", std::process::id(), name));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        p
    }

    #[test]
    fn load_first_existing_candidate_wins() {
        let inv = write_temp("inv.json", r#"{"install_disk":"from_inv"}"#);
        let cfg = write_temp("cfg.json", r#"{"install_disk":"from_config"}"#);
        let missing = std::path::Path::new("/nonexistent/sp1/none.json");
        let (c, w) = load(&[missing, &inv, &cfg], "eve_install_server=ctrl");
        assert_eq!(c.install_disk.as_deref(), Some("from_inv")); // inv wins over cfg
        assert_eq!(c.install_server.as_deref(), Some("ctrl")); // from cmdline
        assert!(w.is_empty());
        std::fs::remove_file(inv).ok();
        std::fs::remove_file(cfg).ok();
    }

    #[test]
    fn load_all_absent_is_cmdline_only() {
        let missing = std::path::Path::new("/nonexistent/sp1/none.json");
        let (c, w) = load(&[missing], "eve_install_disk=sda");
        assert_eq!(c.install_disk.as_deref(), Some("sda"));
        assert!(w.is_empty());
    }

    #[test]
    fn load_garbage_first_file_is_cmdline_only_with_warning() {
        let bad = write_temp("bad.json", "not json");
        let (c, w) = load(&[&bad], "eve_install_disk=sda");
        assert_eq!(c.install_disk.as_deref(), Some("sda")); // cmdline still applied
        assert_eq!(w.len(), 1);
        assert!(matches!(w[0], Warning::BadJson(_)));
        std::fs::remove_file(bad).ok();
    }

    #[test]
    fn load_json_beats_cmdline_for_same_field() {
        let inv = write_temp("prec.json", r#"{"install_disk":"from_json"}"#);
        let (c, _) = load(&[&inv], "eve_install_disk=from_cmdline");
        assert_eq!(c.install_disk.as_deref(), Some("from_json"));
        std::fs::remove_file(inv).ok();
    }

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

    #[test]
    fn json_parses_full_and_partial() {
        let (c, w) = parse_json(r#"{"install_disk":"nvme0n1","persist_fs":"zfs","skip_config":true}"#);
        assert_eq!(c.install_disk.as_deref(), Some("nvme0n1"));
        assert_eq!(c.persist_fs, Some(Fs::Zfs));
        assert_eq!(c.skip_config, Some(true));
        assert!(c.install_server.is_none());
        assert!(w.is_empty());
    }

    #[test]
    fn json_empty_object_is_default() {
        let (c, w) = parse_json("{}");
        assert_eq!(c, InstallConfig::default());
        assert!(w.is_empty());
    }

    #[test]
    fn json_unknown_keys_are_ignored() {
        let (c, w) = parse_json(r#"{"install_disk":"sda","totally_unknown":42}"#);
        assert_eq!(c.install_disk.as_deref(), Some("sda"));
        assert!(w.is_empty());
    }

    #[test]
    fn json_garbage_degrades_to_empty_with_warning() {
        let (c, w) = parse_json("not json at all");
        assert_eq!(c, InstallConfig::default());
        assert_eq!(w.len(), 1);
        assert!(matches!(w[0], Warning::BadJson(_)));
    }

    #[test]
    fn or_prefers_self_then_lower() {
        let high = InstallConfig {
            install_disk: Some("sda".into()),
            ..Default::default()
        };
        let low = InstallConfig {
            install_disk: Some("sdb".into()),
            install_server: Some("ctrl".into()),
            ..Default::default()
        };
        let merged = high.or(low);
        assert_eq!(merged.install_disk.as_deref(), Some("sda")); // self wins
        assert_eq!(merged.install_server.as_deref(), Some("ctrl")); // filled from lower
    }

    #[test]
    fn or_composes_tui_over_json_over_cmdline() {
        let (cmd, _) = parse_cmdline("eve_install_disk=sda eve_install_server=cmdctrl");
        let (json, _) = parse_json(r#"{"install_server":"jsonctrl"}"#);
        let tui = InstallConfig {
            install_disk: Some("nvme0n1".into()),
            ..Default::default()
        };
        // interactive precedence: TUI ▷ (json ▷ cmdline)
        let merged = tui.or(json.or(cmd));
        assert_eq!(merged.install_disk.as_deref(), Some("nvme0n1")); // from TUI
        assert_eq!(merged.install_server.as_deref(), Some("jsonctrl")); // json beats cmdline
    }

    #[test]
    fn to_unattended_strips_per_device_fields() {
        let c = InstallConfig {
            install_disk: Some("sda".into()),
            install_server: Some("ctrl".into()),
            nuke_all_disks: Some(true),
            soft_serial: Some("UNIQUE-123".into()),
            pause_before_install: Some(true),
            pause_after_install: Some(true),
            install_debug: Some(true),
            ..Default::default()
        };
        let json = c.to_unattended();
        // excluded fields absent
        assert!(!json.contains("soft_serial"));
        assert!(!json.contains("UNIQUE-123"));
        assert!(!json.contains("pause_before_install"));
        assert!(!json.contains("pause_after_install"));
        assert!(!json.contains("install_debug"));
        // cloned fields present
        assert!(json.contains("install_disk"));
        assert!(json.contains("install_server"));
        assert!(json.contains("nuke_all_disks"));
    }

    #[test]
    fn to_unattended_reparses_to_same_retained_fields() {
        let c = InstallConfig {
            install_disk: Some("sda".into()),
            soft_serial: Some("UNIQUE-123".into()),
            install_debug: Some(true),
            ..Default::default()
        };
        let (reparsed, w) = parse_json(&c.to_unattended());
        assert!(w.is_empty());
        assert_eq!(reparsed.install_disk.as_deref(), Some("sda"));
        assert!(reparsed.soft_serial.is_none()); // stripped
        assert!(reparsed.install_debug.is_none()); // stripped
    }

    /// Table-driven coverage of every `eve_*` cmdline token (spec §9: "each
    /// token" must be tested). Each entry pairs the exact token string with a
    /// closure that asserts the one field it must set; a wrong match arm in
    /// `parse_cmdline` will make some entry's closure return `false`.
    #[test]
    fn cmdline_every_token_maps_to_its_field() {
        let cases: Vec<(&str, Box<dyn Fn(&InstallConfig) -> bool>)> = vec![
            // value tokens
            (
                "eve_install_disk=sda",
                Box::new(|c: &InstallConfig| c.install_disk == Some("sda".to_string())),
            ),
            (
                "eve_persist_disk=sdb",
                Box::new(|c: &InstallConfig| c.persist_disk == Some(vec!["sdb".to_string()])),
            ),
            (
                "eve_install_server=ctrl",
                Box::new(|c: &InstallConfig| c.install_server == Some("ctrl".to_string())),
            ),
            (
                "eve_soft_serial=serial123",
                Box::new(|c: &InstallConfig| c.soft_serial == Some("serial123".to_string())),
            ),
            (
                "eve_nuke_disks=sde",
                Box::new(|c: &InstallConfig| c.nuke_disks == Some(vec!["sde".to_string()])),
            ),
            (
                "eve_install_zfs_with_raid_level=raid1",
                Box::new(|c: &InstallConfig| {
                    c.zfs_raid_level == Some(RaidLevel::Raid1) && c.persist_fs == Some(Fs::Zfs)
                }),
            ),
            (
                "eve_install_k3s_etcd_sizeGB=10",
                Box::new(|c: &InstallConfig| c.k3s_etcd_size_gb == Some(10)),
            ),
            // bare presence flags
            (
                "eve_install_skip_config",
                Box::new(|c: &InstallConfig| c.skip_config == Some(true)),
            ),
            (
                "eve_install_skip_persist",
                Box::new(|c: &InstallConfig| c.skip_persist == Some(true)),
            ),
            (
                "eve_install_skip_rootfs",
                Box::new(|c: &InstallConfig| c.skip_rootfs == Some(true)),
            ),
            (
                "eve_install_skip_zfs_checks",
                Box::new(|c: &InstallConfig| c.skip_zfs_checks == Some(true)),
            ),
            (
                "eve_disable_verify",
                Box::new(|c: &InstallConfig| c.disable_verify == Some(true)),
            ),
            (
                "eve_skip_dev_cert",
                Box::new(|c: &InstallConfig| c.skip_dev_cert == Some(true)),
            ),
            (
                "eve_reboot_after_install",
                Box::new(|c: &InstallConfig| c.reboot_after_install == Some(true)),
            ),
            (
                "eve_nuke_all_disks",
                Box::new(|c: &InstallConfig| c.nuke_all_disks == Some(true)),
            ),
            (
                "eve_blackbox",
                Box::new(|c: &InstallConfig| c.blackbox == Some(true)),
            ),
            (
                "eve_pause_before_install",
                Box::new(|c: &InstallConfig| c.pause_before_install == Some(true)),
            ),
            (
                "eve_pause_after_install",
                Box::new(|c: &InstallConfig| c.pause_after_install == Some(true)),
            ),
            (
                "eve_install_debug",
                Box::new(|c: &InstallConfig| c.install_debug == Some(true)),
            ),
        ];

        for (token, check) in &cases {
            let (c, w) = parse_cmdline(token);
            assert!(check(&c), "token {:?} did not set the expected field: {:?}", token, c);
            assert!(w.is_empty(), "token {:?} produced unexpected warnings: {:?}", token, w);
        }
    }
}
