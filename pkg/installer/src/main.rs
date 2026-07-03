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
mod execute;
mod facts;
mod installer;
mod plan;
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

fn cmd_install(dry_run: bool) -> Result<()> {
    let mode = if dry_run { crate::execute::Mode::DryRun } else { crate::execute::Mode::Execute };

    if !dry_run && !crate::facts::is_eve_env(&crate::facts::eve_root()) {
        anyhow::bail!(
            "refusing to install: not an EVE installer environment \
             (missing {}/etc/eve-release). Use --dry-run to preview.",
            crate::facts::eve_root().display()
        );
    }

    let hw = crate::facts::gather();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let cfg_candidates = [
        std::path::Path::new("/run/INVENTORY/unattended.json"),
        std::path::Path::new("/config/unattended.json"),
    ];
    let (cfg, cfg_warns) = crate::config::load(&cfg_candidates, &cmdline);
    for w in &cfg_warns {
        eprintln!("[config] {w:?}");
    }

    let (disks, boot, disc_warns) = crate::disk::discover();
    for w in &disc_warns {
        eprintln!("[disk] {w}");
    }

    let (install, persist) = match crate::disk::resolve(&cfg, &disks, boot.as_deref()) {
        crate::disk::DiskResolution::Resolved { install, persist, warnings } => {
            for w in &warnings {
                eprintln!("[resolve] {w}");
            }
            (install, persist)
        }
        crate::disk::DiskResolution::NeedInteractive(reason) => {
            eprintln!("would launch interactive installer: {reason}");
            return Ok(());
        }
    };

    let plan = match crate::plan::plan(&install, &persist, boot.as_deref(), &cfg, &hw) {
        crate::plan::PlanOutcome::Rejected(reason) => anyhow::bail!("install plan rejected: {reason}"),
        crate::plan::PlanOutcome::Ready(p) => {
            for a in &p.advisories {
                eprintln!("[advisory] {a}");
            }
            p
        }
    };

    let log = crate::execute::run(&plan, &install, &persist, &disks, mode)?;
    for line in &log {
        println!("{line}");
    }
    eprintln!("install {}", if dry_run { "(dry-run) complete" } else { "complete" });
    Ok(())
}

fn main() -> Result<()>{
    let mut installer_json = json!(null);
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("disks") {
        return cmd_disks();
    }
    if args.get(1).map(String::as_str) == Some("install") {
        let dry_run = args.iter().any(|a| a == "--dry-run");
        return cmd_install(dry_run);
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
