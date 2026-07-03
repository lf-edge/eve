/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use serde_json::json;
use std::env;
use anyhow::Result;

mod config;
mod disk;
mod execute;
mod facts;
mod plan;
mod tui;

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
             (missing {}/etc/eve-release + eve-hv-type). Use --dry-run to preview.",
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

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("disks") => cmd_disks(),
        Some("install") => cmd_install(args.iter().any(|a| a == "--dry-run")),
        _ => {
            eprintln!("usage: installer <disks|install [--dry-run]>");
            Ok(())
        }
    }
}
