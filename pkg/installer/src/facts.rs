/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

#![allow(dead_code)] // consumed by the install subcommand (Task 3) and SP-2d.

use std::path::{Path, PathBuf};

/// Parse the `MemTotal:` line of /proc/meminfo (kB) into whole GiB. 0 if absent.
pub fn parse_meminfo_gb(meminfo: &str) -> u64 {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
            return kb / 1024 / 1024;
        }
    }
    0
}

/// Base of the EVE root filesystem in the installer (overridable for dev/harness).
pub fn eve_root() -> PathBuf {
    std::env::var_os("EVE_ROOT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/root"))
}

/// True only in a real EVE installer environment: both marker files exist. Used
/// to refuse destructive execution on a developer host.
pub fn is_eve_env(root: &Path) -> bool {
    root.join("etc/eve-release").exists() && root.join("etc/eve-hv-type").exists()
}

/// Gather hardware facts for the planner. Never panics; missing inputs default.
pub fn gather() -> crate::plan::HardwareFacts {
    let root = eve_root();
    let eve_flavor = std::fs::read_to_string(root.join("etc/eve-hv-type"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "kvm".to_string());
    let platform = std::fs::read_to_string(root.join("etc/eve-platform"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let memory_gb = std::fs::read_to_string("/proc/meminfo")
        .map(|s| parse_meminfo_gb(&s))
        .unwrap_or(0);
    crate::plan::HardwareFacts { memory_gb, eve_flavor, platform }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_parses_memtotal_to_gib() {
        let mi = "MemTotal:       65853112 kB\nMemFree: 100 kB\n";
        assert_eq!(parse_meminfo_gb(mi), 62); // 65853112 kB / 1024 / 1024 ≈ 62 GiB
    }

    #[test]
    fn meminfo_absent_memtotal_is_zero() {
        assert_eq!(parse_meminfo_gb("MemFree: 100 kB\n"), 0);
    }

    #[test]
    fn is_eve_env_requires_both_markers() {
        let dir = std::env::temp_dir().join(format!("sp2c_eve_{}", std::process::id()));
        let etc = dir.join("etc");
        std::fs::create_dir_all(&etc).unwrap();
        assert!(!is_eve_env(&dir)); // neither marker
        std::fs::write(etc.join("eve-hv-type"), "kvm\n").unwrap();
        assert!(!is_eve_env(&dir)); // only one
        std::fs::write(etc.join("eve-release"), "0.0.0\n").unwrap();
        assert!(is_eve_env(&dir)); // both
        std::fs::remove_dir_all(&dir).ok();
    }
}
