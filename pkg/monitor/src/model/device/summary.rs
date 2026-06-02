// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use chrono::DateTime;
use chrono::Utc;

use std::process::Command;

use super::network::NetworkInterfaceStatus;

pub fn get_name() -> String {
    "hello world".to_string() // to be replaced with fetch of hostname
}

// Public summary model; some fields are intended API not yet rendered.
#[allow(dead_code)]
#[derive(Debug)]
pub struct DeviceSummary {
    pub name: String,
    pub status: String,
    pub last_checkin: DateTime<Utc>,
    pub network_interfaces: Vec<NetworkInterfaceStatus>,
    pub usb_devices: Vec<String>,
    pub pci_devices: Vec<String>,
}

impl DeviceSummary {
    pub fn dummy_summary() -> DeviceSummary {
        DeviceSummary {
            name: get_name(),
            status: "online".to_string(),
            last_checkin: Utc::now(),
            network_interfaces: Vec::new(),
            usb_devices: get_usb(),
            pci_devices: get_pci(),
        }
    }
}

fn get_usb() -> Vec<String> {
    let cmd_out = Command::new("lsusb")
        .output()
        .expect("failed to execute process");
    if cmd_out.status.success() {
        if let Ok(string) = String::from_utf8(cmd_out.stdout) {
            return string.split('\n').map(|s| s.to_string()).collect();
        }
    }

    vec!["No devices detected".to_string()]
}

fn get_pci() -> Vec<String> {
    let cmd_out = Command::new("lspci")
        .output()
        .expect("failed to execute process");
    if cmd_out.status.success() {
        if let Ok(string) = String::from_utf8(cmd_out.stdout) {
            return string.split('\n').map(|s| s.to_string()).collect();
        }
    }

    vec!["No devices detected".to_string()]
}
