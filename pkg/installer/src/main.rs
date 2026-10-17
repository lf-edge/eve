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

/// Serial/hypervisor console device paths (`/dev/<name>`) from the kernel
/// cmdline's `console=` tokens. Deny-list by design: it drops only the VGA
/// virtual-console meta (`tty0`/`tty`) and keeps everything else, so ARM
/// (`ttyAMA0`), i.MX (`ttymxc*`), hypervisor (`hvc0`), USB (`ttyUSB*`), x86
/// (`ttyS0`), etc. all flow through without per-arch enumeration. Never yields
/// `/dev/console`; the screen is driven separately on tty2. The baud/options
/// suffix (`ttyS0,115200n8`) is stripped and duplicates removed.
fn serial_consoles_from_cmdline(cmdline: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in cmdline.split_whitespace() {
        let Some(val) = tok.strip_prefix("console=") else { continue };
        let name = val.split(',').next().unwrap_or(val);
        if name.is_empty() || name == "tty0" || name == "tty" {
            continue;
        }
        let path = format!("/dev/{name}");
        if !out.contains(&path) {
            out.push(path);
        }
    }
    out
}

fn cmd_install(dry_run: bool) -> Result<()> {
    let interactive = std::env::args().any(|a| a == "--interactive");
    let mode = if dry_run { crate::execute::Mode::DryRun } else { crate::execute::Mode::Execute };

    // Prefill config (unattended.json ▷ cmdline), gather facts, discover disks —
    // shared by both the interactive and unattended paths.
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let cfg_candidates = [
        std::path::Path::new("/run/INVENTORY/unattended.json"),
        std::path::Path::new("/config/unattended.json"),
    ];
    let (mut cfg, cfg_warns) = crate::config::load(&cfg_candidates, &cmdline);
    for w in &cfg_warns {
        eprintln!("[config] {w:?}");
    }

    let hw = crate::facts::gather();
    let (disks, boot, disc_warns) = crate::disk::discover();
    for w in &disc_warns {
        eprintln!("[disk] {w}");
    }

    // Interactive: run the wizard (rendered to tty2 + every serial console) and
    // adopt the confirmed config. Cancelling exits cleanly. The wizard gets
    // clones so the discovered disks remain available for the execute tail.
    if interactive {
        let serial = serial_consoles_from_cmdline(&cmdline);
        match crate::tui::run(disks.clone(), boot.clone(), cfg.clone(), hw.clone(), &serial)? {
            crate::tui::Outcome::Completed(c) => cfg = c,
            crate::tui::Outcome::Cancelled => {
                eprintln!("installation cancelled");
                return Ok(());
            }
        }
    }

    if !dry_run && !crate::facts::is_eve_env(&crate::facts::eve_root()) {
        anyhow::bail!(
            "refusing to install: not an EVE installer environment \
             (missing {}/etc/eve-release + eve-hv-type). Use --dry-run to preview.",
            crate::facts::eve_root().display()
        );
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

#[cfg(test)]
mod tests {
    use super::serial_consoles_from_cmdline;

    #[test]
    fn parses_serial_consoles_excluding_vga_and_dedup() {
        let cmdline = "root=/dev/sda1 console=ttyS0,115200n8 console=tty0 console=ttyAMA0 console=ttyS0";
        assert_eq!(
            serial_consoles_from_cmdline(cmdline),
            vec!["/dev/ttyS0".to_string(), "/dev/ttyAMA0".to_string()]
        );
    }

    #[test]
    fn no_console_tokens_yields_empty() {
        assert!(serial_consoles_from_cmdline("root=/dev/sda1 quiet").is_empty());
    }
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
