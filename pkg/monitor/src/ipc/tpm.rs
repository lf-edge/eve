// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Client-side helpers on the generated `TpmLogs` wire type.

use super::monitorapi::TpmLogs;
use anyhow::Result;
use std::fs::File;
use std::io::Write;

impl TpmLogs {
    /// Dump the raw binary measured-boot logs to `path` for offline analysis.
    /// Empty (absent) logs are skipped.
    pub fn save_raw_binary_logs(&self, path: &str) -> Result<()> {
        for (name, data) in [
            ("last_failed_log", &self.last_failed_log),
            ("last_good_log", &self.last_good_log),
            ("backup_failed_log", &self.backup_failed_log),
            ("backup_good_log", &self.backup_good_log),
        ] {
            if !data.is_empty() {
                File::create(format!("{path}/{name}.bin"))?.write_all(data)?;
            }
        }
        Ok(())
    }
}
