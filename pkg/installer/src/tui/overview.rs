/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::screen::{Nav, Screen};
use super::state::WizardState;
use super::theme;
use crate::config::Fs;
use crate::disk::Disk;
use crate::plan::{plan, InstallPlan, NukePlan, PersistDevice, PersistPlan, PlanOutcome, PoolMember};

/// Final screen: build the install plan from the accumulated config and preview
/// it. Confirmation is only allowed when the plan is `Ready`; a `Rejected` plan
/// (or an incomplete config) shows the reason and blocks confirm, leaving back /
/// quit. The screen re-derives the plan on every render/key so it always
/// reflects edits made via Back.
pub struct OverviewScreen;

impl OverviewScreen {
    pub fn new() -> Self {
        OverviewScreen
    }

    /// Assemble `plan::plan` inputs from state. `Err` means the config is
    /// incomplete (no install disk) — distinct from a planner rejection.
    fn build_plan(state: &WizardState) -> Result<PlanOutcome, String> {
        let install = state
            .disks
            .iter()
            .find(|d| Some(&d.name) == state.config.install_disk.as_ref())
            .ok_or_else(|| "no install disk selected".to_string())?;
        let names: Vec<String> = match state.config.persist_disk.as_ref() {
            Some(v) if !v.is_empty() => v.clone(),
            _ => vec![install.name.clone()],
        };
        let persist: Vec<Disk> = names
            .iter()
            .filter_map(|n| state.disks.iter().find(|d| &d.name == n).cloned())
            .collect();
        Ok(plan(install, &persist, state.boot.as_deref(), &state.config, &state.hw))
    }

    fn format_ready(p: &InstallPlan) -> Vec<Line<'static>> {
        let mut lines: Vec<Line> = Vec::new();
        let fs = match p.fs {
            Fs::Ext4 => "ext4",
            Fs::Zfs => "zfs",
        };
        lines.push(Line::from(format!("Filesystem:  {fs}")));

        let persist = match &p.persist {
            PersistPlan::Ext4 { device } => match device {
                PersistDevice::P3OnInstallDisk => "ext4 on a P3 partition of the install disk".to_string(),
                PersistDevice::SeparateDisk(p) => format!("ext4 on {p}"),
            },
            PersistPlan::Zfs { members, raid, clustered } => {
                let parts: Vec<String> = members
                    .iter()
                    .map(|m| match m {
                        PoolMember::P3OnInstallDisk => "install-disk(P3)".to_string(),
                        PoolMember::WholeDisk(p) => p.clone(),
                    })
                    .collect();
                format!(
                    "zfs pool {:?}{}: {}",
                    raid,
                    if *clustered { " (clustered)" } else { "" },
                    parts.join(" + ")
                )
            }
        };
        lines.push(Line::from(format!("Persist:     {persist}")));

        let nuke = match &p.nuke {
            NukePlan::None => "none".to_string(),
            NukePlan::Disks(v) => v.join(", "),
            NukePlan::AllDisks => "ALL disks".to_string(),
        };
        lines.push(Line::from(format!("Nuke:        {nuke}")));

        for a in &p.advisories {
            lines.push(Line::styled(format!("! {a}"), theme::advisory()));
        }
        lines.push(Line::from(""));
        lines.push(Line::styled("Enter/c confirm · b back · q quit", theme::hint()));
        lines
    }

    fn format_blocked(reason: String) -> Vec<Line<'static>> {
        vec![
            Line::styled(reason, theme::error()),
            Line::from(""),
            Line::styled("b back · q quit", theme::hint()),
        ]
    }
}

impl Default for OverviewScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen for OverviewScreen {
    fn title(&self) -> &str {
        "Overview"
    }

    fn render(&mut self, f: &mut Frame, area: Rect, state: &WizardState) {
        let lines = match Self::build_plan(state) {
            Ok(PlanOutcome::Ready(p)) => Self::format_ready(&p),
            Ok(PlanOutcome::Rejected(r)) => Self::format_blocked(format!("Cannot install: {r}")),
            Err(e) => Self::format_blocked(format!("Configuration incomplete: {e}")),
        };
        let para = Paragraph::new(lines).style(theme::dialog());
        f.render_widget(para, area);
    }

    fn handle_key(&mut self, key: KeyEvent, state: &mut WizardState) -> Nav {
        match key.code {
            KeyCode::Enter | KeyCode::Char('c') => {
                match Self::build_plan(state) {
                    Ok(PlanOutcome::Ready(_)) => Nav::Next, // finish -> Outcome::Completed
                    _ => Nav::Stay,
                }
            }
            KeyCode::Char('b') | KeyCode::Left => Nav::Back,
            KeyCode::Char('q') | KeyCode::Esc => Nav::Quit,
            _ => Nav::Stay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InstallConfig, RaidLevel};
    use crate::plan::HardwareFacts;
    use ratatui::crossterm::event::{KeyCode, KeyEvent};
    use ratatui::{backend::TestBackend, Terminal};

    fn disk(name: &str) -> Disk {
        Disk {
            name: name.into(),
            path: format!("/dev/{name}"),
            kind: "disk".into(),
            size_bytes: 40_000_000_000,
            transport: None,
            model: None,
            serial: None,
            read_only: false,
            virtual_dev: false,
            partitions: vec![],
        }
    }
    fn hw() -> HardwareFacts {
        HardwareFacts { memory_gb: 8, eve_flavor: "kvm".into(), platform: "generic".into() }
    }
    fn state() -> WizardState {
        let mut config = InstallConfig::default();
        config.install_disk = Some("vdb".into());
        config.persist_fs = Some(Fs::Ext4);
        config.persist_disk = Some(vec!["vdb".into()]);
        WizardState {
            disks: vec![disk("vda"), disk("vdb"), disk("vdc")],
            boot: Some("vda".into()),
            config,
            hw: hw(),
        }
    }
    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::from(c)
    }
    fn buf_text(t: &Terminal<TestBackend>) -> String {
        t.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn ready_plan_renders_and_confirms() {
        let mut scr = OverviewScreen::new();
        let mut st = state();
        let mut term = Terminal::new(TestBackend::new(90, 14)).unwrap();
        term.draw(|f| scr.render(f, f.area(), &st)).unwrap();
        let s = buf_text(&term);
        assert!(s.contains("Filesystem"));
        assert!(s.contains("ext4"));
        assert!(s.contains("Persist"));
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Next);
    }

    #[test]
    fn rejected_plan_blocks_confirm() {
        let mut scr = OverviewScreen::new();
        let mut st = state();
        // raid6 needs 4 disks; only one selected -> planner rejects
        st.config.persist_fs = Some(Fs::Zfs);
        st.config.zfs_raid_level = Some(RaidLevel::Raid6);
        st.config.persist_disk = Some(vec!["vdb".into()]);
        let mut term = Terminal::new(TestBackend::new(90, 14)).unwrap();
        term.draw(|f| scr.render(f, f.area(), &st)).unwrap();
        assert!(buf_text(&term).contains("Cannot install"));
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Stay);
        assert_eq!(scr.handle_key(key(KeyCode::Char('b')), &mut st), Nav::Back);
    }

    #[test]
    fn incomplete_config_blocks_confirm() {
        let mut scr = OverviewScreen::new();
        let mut st = state();
        st.config.install_disk = None;
        let mut term = Terminal::new(TestBackend::new(90, 14)).unwrap();
        term.draw(|f| scr.render(f, f.area(), &st)).unwrap();
        assert!(buf_text(&term).contains("incomplete"));
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Stay);
    }
}
