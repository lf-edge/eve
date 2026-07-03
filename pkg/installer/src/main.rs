/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use serde_json::json;
use std::env;
use crate::utils::read_installer_json;
use anyhow::Result;

mod actions;
mod config;
mod data;
mod disk;
mod error;
mod installer;
mod state;
mod utils;
mod views;

fn help() {
    println!(
        "Usage: tui-cursive <installer.json>
    input file <installer.json> is optional."
    );
}

fn cmd_disks() -> Result<()> {
    let (disks, boot, mut warnings) = crate::disk::discover();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let (cfg, w2) = crate::config::parse_cmdline(&cmdline);
    // `config::Warning` has no Display/Serialize impl; render via Debug so it
    // fits the same `Vec<String>` warnings channel `disk::discover` uses.
    warnings.extend(w2.into_iter().map(|w| format!("{:?}", w)));
    let resolution = crate::disk::resolve(&cfg, &disks, boot.as_deref());
    let out = json!({
        "disks": disks,
        "boot_disk": boot,
        "resolution": resolution,
        "warnings": warnings,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn main() -> Result<()>{
    let mut installer_json = json!(null);
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("disks") {
        return cmd_disks();
    }

    match args.len() {
        // no arguments passed
        1 => {
            println!("Interactive installer mode!");
        }
        2 => {
            installer_json = read_installer_json(&args[1])?
        }
        // all the other cases
        _ => {
            // show a help message
            help();
        }
    }

    println!("Initializing EVE config!");
    installer::config(installer_json);

    Ok(())
}
