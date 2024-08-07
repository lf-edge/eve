/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub const INSTALL_SERVER: &str = "Eve_install_server";
pub const INSTALL_DISK: &str = "Eve_install_disk";
pub const PERSIST_DISK: &str = "Eve_persist_disk";
pub const SOFT_SERIAL: &str = "Eve_soft_serial";
pub const REBOOT_AFTER_INSTALL: &str = "Eve_reboot_after_install";
pub const PAUSE_AFTER_INSTALL: &str = "Eve_pause_after_install";
pub const PAUSE_BEFORE_INSTALL: &str = "Eve_pause_before_install";
pub const ROOT: &str = "Root";
pub const FIND_BOOT: &str = "Find_boot";
pub const CONSOLE: &str = "Console";
pub const CONFIG: &str = "General Config";
pub const INIT: &str = "INIT";
pub const FS: &str = "FS";
pub const BUTTONS: &str = "Buttons";
pub const RAID: &str = "Eve_install_zfs_with_raid_level";
pub const OVERVIEW: &str = "Overview";
pub const INSTALLER_CFG_OUT: &str = "installer.json";
pub const INTERACTIVE_MODE: &str = "Interactive";

pub const LABELS: [&str; 14] = [
    INTERACTIVE_MODE,
    INIT,
    FS,
    RAID,
    INSTALL_SERVER,
    INSTALL_DISK,
    PERSIST_DISK,
    SOFT_SERIAL,
    REBOOT_AFTER_INSTALL,
    PAUSE_AFTER_INSTALL,
    PAUSE_BEFORE_INSTALL,
    ROOT,
    FIND_BOOT,
    CONSOLE,
];
const VALUES: [&str; 14] = [
    "true", "", "", "", "", "_____", "_____", "", "", "", "", "", "", "",
];

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Data {
    pub map: HashMap<String, String>,
}

impl Data {
    pub fn new(in_json: Value) -> Self {
        let mut data = Self {
            map: HashMap::new(),
        };
        for (i, label) in LABELS.iter().enumerate() {
            data.map.insert(label.to_string(), VALUES[i].to_string());
        }
        if !in_json.is_null() {
            //Replace initial values with user inserted values
            for (k, v) in in_json.as_object().unwrap() {
                data.map
                    .insert(k.to_string(), v.as_str().unwrap().to_string());
            }
        }
        data
    }

    pub fn write(&mut self, fname: &str) -> Result<(), std::io::Error> {
        // Save the JSON structure into the other file.
        std::fs::write(fname, serde_json::to_string_pretty(&self.map).unwrap())
    }
}
