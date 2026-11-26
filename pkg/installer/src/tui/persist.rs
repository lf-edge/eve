/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::screen::{Nav, Screen};
use super::state::WizardState;
use super::theme;
use super::util::human_size;
use crate::config::{Fs, RaidLevel};
use crate::plan::raid_min_disks;

/// Persist-location screen. Its mode is derived from config each time it is
/// entered/rendered:
///   * single-select (ext4, or zfs with no raid): "same as install disk" or a
///     separate whole disk;
///   * multi-select (zfs + raid1/5/6): pick >= `raid_min_disks` pool members.
/// The source of truth for the selection is `config.persist_disk`; the cursor
/// is the only local state.
pub struct PersistScreen {
    cursor: usize,
}

impl PersistScreen {
    pub fn new() -> Self {
        PersistScreen { cursor: 0 }
    }

    fn is_raid(state: &WizardState) -> bool {
        state.config.persist_fs == Some(Fs::Zfs)
            && matches!(
                state.config.zfs_raid_level,
                Some(RaidLevel::Raid1) | Some(RaidLevel::Raid5) | Some(RaidLevel::Raid6)
            )
    }

    fn install_name(state: &WizardState) -> Option<String> {
        state.config.install_disk.clone()
    }

    /// Indices of non-boot disks, in disk order (the raid member candidates).
    fn non_boot(state: &WizardState) -> Vec<usize> {
        state
            .disks
            .iter()
            .enumerate()
            .filter(|(_, d)| state.boot.as_deref() != Some(d.name.as_str()))
            .map(|(i, _)| i)
            .collect()
    }

    /// Indices of separate-disk candidates for single mode: non-boot and not the
    /// install disk (the install disk is offered only as "same as install").
    fn separate(state: &WizardState) -> Vec<usize> {
        let inst = Self::install_name(state);
        Self::non_boot(state)
            .into_iter()
            .filter(|&i| Some(&state.disks[i].name) != inst.as_ref())
            .collect()
    }

    fn raid_name(level: RaidLevel) -> &'static str {
        match level {
            RaidLevel::None => "none",
            RaidLevel::Raid1 => "raid1",
            RaidLevel::Raid5 => "raid5",
            RaidLevel::Raid6 => "raid6",
        }
    }

    fn selected_count(state: &WizardState) -> usize {
        state.config.persist_disk.as_ref().map(|v| v.len()).unwrap_or(0)
    }

    // ---- rendering ----

    fn render_single(&self, state: &WizardState) -> Vec<Line<'static>> {
        let inst = Self::install_name(state);
        let sep = Self::separate(state);
        // Which row is currently selected (0 == same-as-install).
        let selected_row = match state.config.persist_disk.as_ref() {
            Some(v) if v.len() == 1 => {
                if Some(&v[0]) == inst.as_ref() {
                    0
                } else {
                    sep.iter().position(|&i| state.disks[i].name == v[0]).map(|p| p + 1).unwrap_or(0)
                }
            }
            _ => 0,
        };

        let mut lines: Vec<Line> = Vec::new();
        let row_span = |row: usize, cursor: usize, text: String| -> Line {
            let cur = if row == cursor { "> " } else { "  " };
            let style = if row == cursor { theme::selected() } else { theme::dialog() };
            Line::from(Span::styled(format!("{cur}{text}"), style))
        };
        let radio = |on: bool| if on { "(o)" } else { "( )" };

        lines.push(row_span(
            0,
            self.cursor,
            format!(
                "{} Same as install disk ({}) — EVE creates a P3 partition",
                radio(selected_row == 0),
                inst.as_deref().unwrap_or("?"),
            ),
        ));
        for (j, &di) in sep.iter().enumerate() {
            let row = j + 1;
            let d = &state.disks[di];
            lines.push(row_span(
                row,
                self.cursor,
                format!(
                    "{} {}  {}  (separate whole disk)",
                    radio(selected_row == row),
                    d.name,
                    human_size(d.size_bytes),
                ),
            ));
        }
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "↑/↓ move · Enter select · n next · b back · q quit",
            theme::hint(),
        ));
        lines
    }

    fn render_raid(&self, state: &WizardState) -> Vec<Line<'static>> {
        let level = state.config.zfs_raid_level.unwrap_or(RaidLevel::None);
        let need = raid_min_disks(level);
        let cands = Self::non_boot(state);
        let inst = Self::install_name(state);
        let members = state.config.persist_disk.clone().unwrap_or_default();

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(format!(
            "{} pool — select ≥ {} member disks:",
            Self::raid_name(level),
            need
        )));
        for (pos, &di) in cands.iter().enumerate() {
            let d = &state.disks[di];
            let checked = members.contains(&d.name);
            let is_install = Some(&d.name) == inst.as_ref();
            let cur = if pos == self.cursor { "> " } else { "  " };
            let tail = if is_install { "  (install disk — P3)" } else { "" };
            let text = format!(
                "{cur}{} {}  {}{}",
                if checked { "[x]" } else { "[ ]" },
                d.name,
                human_size(d.size_bytes),
                tail
            );
            let style = if pos == self.cursor { theme::selected() } else { theme::dialog() };
            lines.push(Line::from(Span::styled(text, style)));
        }
        // Show the boot disk grayed out so it is clear why it is not selectable.
        if let Some(boot) = state.boot.as_deref() {
            if let Some(d) = state.disks.iter().find(|d| d.name == boot) {
                lines.push(Line::from(Span::styled(
                    format!("  [ ] {}  {}  (boot — unavailable)", d.name, human_size(d.size_bytes)),
                    theme::disabled(),
                )));
            }
        }
        let have = Self::selected_count(state);
        lines.push(Line::from(format!("selected: {have} / need ≥ {need}")));
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "↑/↓ move · Space toggle · n next · b back · q quit",
            theme::hint(),
        ));
        lines
    }

    // ---- key handling ----

    fn toggle_member(&self, di: usize, state: &mut WizardState) {
        let name = state.disks[di].name.clone();
        let mut set: Vec<String> = state.config.persist_disk.clone().unwrap_or_default();
        if let Some(pos) = set.iter().position(|n| n == &name) {
            set.remove(pos);
        } else {
            set.push(name);
        }
        // Normalize to non-boot candidates in disk order for a deterministic list.
        let ordered: Vec<String> = Self::non_boot(state)
            .iter()
            .map(|&i| state.disks[i].name.clone())
            .filter(|n| set.contains(n))
            .collect();
        state.config.persist_disk = if ordered.is_empty() { None } else { Some(ordered) };
    }
}

impl Default for PersistScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen for PersistScreen {
    fn title(&self) -> &str {
        "Persist storage"
    }

    fn on_enter(&mut self, state: &mut WizardState) {
        self.cursor = 0;
        if Self::is_raid(state) {
            // Keep only valid (non-boot) members, in disk order; seed the install
            // disk if nothing valid is selected.
            let cands: Vec<String> =
                Self::non_boot(state).iter().map(|&i| state.disks[i].name.clone()).collect();
            let current = state.config.persist_disk.clone().unwrap_or_default();
            let mut kept: Vec<String> = cands.iter().filter(|n| current.contains(n)).cloned().collect();
            if kept.is_empty() {
                if let Some(inst) = Self::install_name(state) {
                    if cands.contains(&inst) {
                        kept.push(inst);
                    }
                }
            }
            state.config.persist_disk = if kept.is_empty() { None } else { Some(kept) };
        } else {
            // Single mode: a valid selection is [install] or [one separate disk];
            // anything else (unset, or stale multi-disk from raid) resets to the
            // same-as-install default.
            let inst = Self::install_name(state);
            let sep: Vec<String> =
                Self::separate(state).iter().map(|&i| state.disks[i].name.clone()).collect();
            let valid = matches!(
                state.config.persist_disk.as_ref(),
                Some(v) if v.len() == 1 && (Some(&v[0]) == inst.as_ref() || sep.contains(&v[0]))
            );
            if !valid {
                state.config.persist_disk = inst.clone().map(|i| vec![i]);
            }
            // Cursor onto the selected row.
            if let Some(v) = state.config.persist_disk.as_ref() {
                if v.len() == 1 {
                    if Some(&v[0]) == inst.as_ref() {
                        self.cursor = 0;
                    } else if let Some(p) = sep.iter().position(|n| n == &v[0]) {
                        self.cursor = p + 1;
                    }
                }
            }
        }
    }

    fn render(&mut self, f: &mut Frame, area: Rect, state: &WizardState) {
        let lines = if Self::is_raid(state) {
            self.render_raid(state)
        } else {
            self.render_single(state)
        };
        let para = Paragraph::new(lines).style(theme::dialog());
        f.render_widget(para, area);
    }

    fn handle_key(&mut self, key: KeyEvent, state: &mut WizardState) -> Nav {
        if Self::is_raid(state) {
            let cands = Self::non_boot(state);
            match key.code {
                KeyCode::Up => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                    }
                    Nav::Stay
                }
                KeyCode::Down => {
                    if self.cursor + 1 < cands.len() {
                        self.cursor += 1;
                    }
                    Nav::Stay
                }
                KeyCode::Char(' ') | KeyCode::Enter => {
                    if let Some(&di) = cands.get(self.cursor) {
                        self.toggle_member(di, state);
                    }
                    Nav::Stay
                }
                KeyCode::Char('n') | KeyCode::Right => {
                    let need = raid_min_disks(state.config.zfs_raid_level.unwrap_or(RaidLevel::None));
                    if Self::selected_count(state) >= need {
                        Nav::Next
                    } else {
                        Nav::Stay
                    }
                }
                KeyCode::Char('b') | KeyCode::Left => Nav::Back,
                KeyCode::Char('q') | KeyCode::Esc => Nav::Quit,
                _ => Nav::Stay,
            }
        } else {
            let sep = Self::separate(state);
            let rows = 1 + sep.len(); // row 0 = same-as-install
            match key.code {
                KeyCode::Up => {
                    if self.cursor > 0 {
                        self.cursor -= 1;
                    }
                    Nav::Stay
                }
                KeyCode::Down => {
                    if self.cursor + 1 < rows {
                        self.cursor += 1;
                    }
                    Nav::Stay
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    if self.cursor == 0 {
                        state.config.persist_disk = Self::install_name(state).map(|i| vec![i]);
                    } else if let Some(&di) = sep.get(self.cursor - 1) {
                        state.config.persist_disk = Some(vec![state.disks[di].name.clone()]);
                    }
                    Nav::Stay
                }
                KeyCode::Char('n') | KeyCode::Right => Nav::Next,
                KeyCode::Char('b') | KeyCode::Left => Nav::Back,
                KeyCode::Char('q') | KeyCode::Esc => Nav::Quit,
                _ => Nav::Stay,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InstallConfig;
    use crate::disk::Disk;
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
    // vda = boot, vdb = install, plus extra disks by name.
    fn state(extra: &[&str]) -> WizardState {
        let mut disks = vec![disk("vda"), disk("vdb")];
        for n in extra {
            disks.push(disk(n));
        }
        let mut config = InstallConfig::default();
        config.install_disk = Some("vdb".into());
        WizardState { disks, boot: Some("vda".into()), config, hw: hw() }
    }
    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::from(c)
    }
    fn buf_text(t: &Terminal<TestBackend>) -> String {
        t.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn single_mode_defaults_to_same_as_install() {
        let mut scr = PersistScreen::new();
        let mut st = state(&["vdc"]);
        st.config.persist_fs = Some(Fs::Ext4);
        scr.on_enter(&mut st);
        assert_eq!(st.config.persist_disk.as_deref(), Some(&["vdb".to_string()][..]));
        let mut term = Terminal::new(TestBackend::new(80, 12)).unwrap();
        term.draw(|f| scr.render(f, f.area(), &st)).unwrap();
        let s = buf_text(&term);
        assert!(s.contains("Same as install"));
        assert!(s.contains("vdc")); // the separate candidate
    }

    #[test]
    fn single_mode_select_separate_disk() {
        let mut scr = PersistScreen::new();
        let mut st = state(&["vdc"]);
        st.config.persist_fs = Some(Fs::Ext4);
        scr.on_enter(&mut st); // cursor 0 (same-as-install)
        assert_eq!(scr.handle_key(key(KeyCode::Down), &mut st), Nav::Stay); // -> vdc
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Stay);
        assert_eq!(st.config.persist_disk.as_deref(), Some(&["vdc".to_string()][..]));
        assert_eq!(scr.handle_key(key(KeyCode::Char('n')), &mut st), Nav::Next);
    }

    #[test]
    fn single_mode_resets_stale_multi_selection() {
        let mut scr = PersistScreen::new();
        let mut st = state(&["vdc", "vdd"]);
        st.config.persist_fs = Some(Fs::Ext4);
        // stale multi-disk value left over from a raid choice
        st.config.persist_disk = Some(vec!["vdb".into(), "vdc".into(), "vdd".into()]);
        scr.on_enter(&mut st);
        assert_eq!(st.config.persist_disk.as_deref(), Some(&["vdb".to_string()][..]));
    }

    #[test]
    fn raid_mode_seeds_install_and_gates_next_on_min() {
        let mut scr = PersistScreen::new();
        let mut st = state(&["vdc", "vdd", "vde"]);
        st.config.persist_fs = Some(Fs::Zfs);
        st.config.zfs_raid_level = Some(RaidLevel::Raid5); // needs 3
        scr.on_enter(&mut st);
        assert_eq!(st.config.persist_disk.as_deref(), Some(&["vdb".to_string()][..])); // seeded install
        assert_eq!(scr.handle_key(key(KeyCode::Char('n')), &mut st), Nav::Stay); // 1 < 3

        // add vdc and vdd
        scr.handle_key(key(KeyCode::Down), &mut st); // -> vdc
        scr.handle_key(key(KeyCode::Char(' ')), &mut st);
        scr.handle_key(key(KeyCode::Down), &mut st); // -> vdd
        scr.handle_key(key(KeyCode::Char(' ')), &mut st);
        assert_eq!(st.config.persist_disk.as_deref(), Some(&["vdb".to_string(), "vdc".to_string(), "vdd".to_string()][..]));
        assert_eq!(scr.handle_key(key(KeyCode::Char('n')), &mut st), Nav::Next); // 3 >= 3

        // toggling one back off drops below min again
        scr.handle_key(key(KeyCode::Char(' ')), &mut st); // untoggle vdd (cursor still on it)
        assert_eq!(scr.handle_key(key(KeyCode::Char('n')), &mut st), Nav::Stay);
    }

    #[test]
    fn raid_mode_shows_boot_disk_grayed_and_excludes_it() {
        let mut scr = PersistScreen::new();
        let mut st = state(&["vdc", "vdd"]);
        st.config.persist_fs = Some(Fs::Zfs);
        st.config.zfs_raid_level = Some(RaidLevel::Raid1);
        scr.on_enter(&mut st);
        let mut term = Terminal::new(TestBackend::new(80, 14)).unwrap();
        term.draw(|f| scr.render(f, f.area(), &st)).unwrap();
        let s = buf_text(&term);
        assert!(s.contains("boot")); // boot disk shown grayed
        // boot disk (vda) can never become a member
        st.config.persist_disk = Some(vec!["vda".into(), "vdb".into()]);
        scr.on_enter(&mut st);
        assert!(!st.config.persist_disk.as_ref().unwrap().contains(&"vda".to_string()));
    }
}
