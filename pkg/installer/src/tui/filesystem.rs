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
use crate::config::{Fs, RaidLevel};

// Row identities in the vertical list. The two fs rows are always present; the
// four raid rows are only focusable (and undimmed) when zfs is selected.
const ROW_EXT4: usize = 0;
const ROW_ZFS: usize = 1;
const ROW_RAID_NONE: usize = 2;
const ROW_RAID1: usize = 3;
const ROW_RAID5: usize = 4;
const ROW_RAID6: usize = 5;

/// Filesystem choice (ext4 | zfs) plus, for zfs, the raid level. Writes
/// `config.persist_fs` and `config.zfs_raid_level`. Choosing ext4 clears any
/// previously-set raid level so a later screen can't be misled into a zfs pool.
pub struct FilesystemScreen {
    cursor: usize, // index into the focusable-row list
}

impl FilesystemScreen {
    pub fn new() -> Self {
        FilesystemScreen { cursor: 0 }
    }

    /// The effective fs for display: unset means the ext4 default.
    fn fs(state: &WizardState) -> Fs {
        state.config.persist_fs.unwrap_or(Fs::Ext4)
    }

    /// Row ids the cursor may land on, in order. The raid rows join only under zfs.
    fn focusable(state: &WizardState) -> Vec<usize> {
        if Self::fs(state) == Fs::Zfs {
            vec![ROW_EXT4, ROW_ZFS, ROW_RAID_NONE, ROW_RAID1, ROW_RAID5, ROW_RAID6]
        } else {
            vec![ROW_EXT4, ROW_ZFS]
        }
    }

    fn row_to_raid(row: usize) -> Option<RaidLevel> {
        match row {
            ROW_RAID_NONE => Some(RaidLevel::None),
            ROW_RAID1 => Some(RaidLevel::Raid1),
            ROW_RAID5 => Some(RaidLevel::Raid5),
            ROW_RAID6 => Some(RaidLevel::Raid6),
            _ => None,
        }
    }

    /// Commit the choice under the cursor into config.
    fn activate(row: usize, state: &mut WizardState) {
        match row {
            ROW_EXT4 => {
                state.config.persist_fs = Some(Fs::Ext4);
                state.config.zfs_raid_level = None; // ext4 can't carry a raid level
            }
            ROW_ZFS => {
                state.config.persist_fs = Some(Fs::Zfs);
                if state.config.zfs_raid_level.is_none() {
                    state.config.zfs_raid_level = Some(RaidLevel::None);
                }
            }
            _ => {
                if let Some(level) = Self::row_to_raid(row) {
                    state.config.persist_fs = Some(Fs::Zfs);
                    state.config.zfs_raid_level = Some(level);
                }
            }
        }
    }
}

impl Default for FilesystemScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen for FilesystemScreen {
    fn title(&self) -> &str {
        "Filesystem"
    }

    fn on_enter(&mut self, state: &mut WizardState) {
        // Land the cursor on the currently-selected option (prefill / return via Back).
        let target = match Self::fs(state) {
            Fs::Ext4 => ROW_EXT4,
            Fs::Zfs => match state.config.zfs_raid_level.unwrap_or(RaidLevel::None) {
                RaidLevel::None => ROW_RAID_NONE,
                RaidLevel::Raid1 => ROW_RAID1,
                RaidLevel::Raid5 => ROW_RAID5,
                RaidLevel::Raid6 => ROW_RAID6,
            },
        };
        let f = Self::focusable(state);
        self.cursor = f.iter().position(|&r| r == target).unwrap_or(0);
    }

    fn render(&mut self, f: &mut Frame, area: Rect, state: &WizardState) {
        let fs = Self::fs(state);
        let is_zfs = fs == Fs::Zfs;
        let level = state.config.zfs_raid_level.unwrap_or(RaidLevel::None);
        let focus = Self::focusable(state);
        let cursor_row = focus.get(self.cursor).copied();

        let radio = |on: bool| if on { "(o)" } else { "( )" };
        let row_line = |row: usize, text: String, dim: bool| -> Line {
            let marker = if Some(row) == cursor_row { " > " } else { "   " };
            let style = if Some(row) == cursor_row {
                theme::selected()
            } else if dim {
                theme::disabled()
            } else {
                theme::dialog()
            };
            Line::from(Span::styled(format!("{marker}{text}"), style))
        };

        let mut lines: Vec<Line> = Vec::new();
        lines.push(row_line(
            ROW_EXT4,
            format!("{} ext4   — single disk, simplest", radio(fs == Fs::Ext4)),
            false,
        ));
        lines.push(row_line(
            ROW_ZFS,
            format!("{} zfs    — pool; multiple disks / RAID", radio(is_zfs)),
            false,
        ));
        lines.push(Line::from("     raid level:"));
        for (row, lvl, name) in [
            (ROW_RAID_NONE, RaidLevel::None, "none"),
            (ROW_RAID1, RaidLevel::Raid1, "raid1"),
            (ROW_RAID5, RaidLevel::Raid5, "raid5"),
            (ROW_RAID6, RaidLevel::Raid6, "raid6"),
        ] {
            let sel = is_zfs && level == lvl;
            lines.push(row_line(row, format!("      {} {name}", radio(sel)), !is_zfs));
        }
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "↑/↓ move · Enter/Space choose · n next · b back · q quit",
            theme::hint(),
        ));

        let para = Paragraph::new(lines).style(theme::dialog());
        f.render_widget(para, area);
    }

    fn handle_key(&mut self, key: KeyEvent, state: &mut WizardState) -> Nav {
        let focus = Self::focusable(state);
        match key.code {
            KeyCode::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
                Nav::Stay
            }
            KeyCode::Down => {
                if self.cursor + 1 < focus.len() {
                    self.cursor += 1;
                }
                Nav::Stay
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(&row) = focus.get(self.cursor) {
                    Self::activate(row, state);
                }
                // The focusable set may have shrunk (ext4) — keep the cursor valid.
                let f = Self::focusable(state);
                if self.cursor >= f.len() {
                    self.cursor = f.len().saturating_sub(1);
                }
                Nav::Stay
            }
            KeyCode::Char('n') | KeyCode::Right => {
                // Leaving the screen commits the shown default (ext4) if untouched.
                if state.config.persist_fs.is_none() {
                    state.config.persist_fs = Some(Fs::Ext4);
                }
                Nav::Next
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
    fn state() -> WizardState {
        WizardState {
            disks: vec![disk("vda"), disk("vdb")],
            boot: Some("vda".into()),
            config: InstallConfig::default(),
            hw: HardwareFacts { memory_gb: 8, eve_flavor: "kvm".into(), platform: "generic".into() },
        }
    }
    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::from(c)
    }
    fn buf_text(t: &Terminal<TestBackend>) -> String {
        t.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn renders_options() {
        let mut scr = FilesystemScreen::new();
        let st = state();
        let mut term = Terminal::new(TestBackend::new(80, 20)).unwrap();
        term.draw(|f| scr.render(f, f.area(), &st)).unwrap();
        let s = buf_text(&term);
        assert!(s.contains("ext4"));
        assert!(s.contains("zfs"));
        assert!(s.contains("raid"));
        assert!(s.contains("raid5"));
    }

    #[test]
    fn default_is_ext4_and_raid_rows_not_focusable() {
        let scr = FilesystemScreen::new();
        let st = state();
        assert_eq!(FilesystemScreen::fs(&st), Fs::Ext4);
        // Only the two fs rows are reachable while ext4 is selected.
        assert_eq!(FilesystemScreen::focusable(&st).len(), 2);
        // scr unused beyond construction; silence the lint intent.
        let _ = scr;
    }

    #[test]
    fn choosing_zfs_sets_fs_and_default_raid_none() {
        let mut scr = FilesystemScreen::new();
        let mut st = state();
        scr.on_enter(&mut st); // cursor -> ext4
        assert_eq!(scr.handle_key(key(KeyCode::Down), &mut st), Nav::Stay); // -> zfs
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Stay);
        assert_eq!(st.config.persist_fs, Some(Fs::Zfs));
        assert_eq!(st.config.zfs_raid_level, Some(RaidLevel::None));
        // raid rows are now focusable
        assert_eq!(FilesystemScreen::focusable(&st).len(), 6);
    }

    #[test]
    fn choosing_raid5_selects_zfs_and_level() {
        let mut scr = FilesystemScreen::new();
        let mut st = state();
        st.config.persist_fs = Some(Fs::Zfs);
        st.config.zfs_raid_level = Some(RaidLevel::None);
        scr.on_enter(&mut st); // cursor -> raid none (row 2, position 2)
        // move down to raid5 (none -> raid1 -> raid5) and select
        scr.handle_key(key(KeyCode::Down), &mut st);
        scr.handle_key(key(KeyCode::Down), &mut st);
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Stay);
        assert_eq!(st.config.persist_fs, Some(Fs::Zfs));
        assert_eq!(st.config.zfs_raid_level, Some(RaidLevel::Raid5));
    }

    #[test]
    fn choosing_ext4_clears_raid_level() {
        let mut scr = FilesystemScreen::new();
        let mut st = state();
        st.config.persist_fs = Some(Fs::Zfs);
        st.config.zfs_raid_level = Some(RaidLevel::Raid5);
        scr.on_enter(&mut st); // cursor -> raid5 row
        // go back up to the ext4 row (raid5 pos4 -> ... -> ext4 pos0) and select
        for _ in 0..4 {
            scr.handle_key(key(KeyCode::Up), &mut st);
        }
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Stay);
        assert_eq!(st.config.persist_fs, Some(Fs::Ext4));
        assert_eq!(st.config.zfs_raid_level, None);
    }

    #[test]
    fn next_commits_ext4_default_and_advances() {
        let mut scr = FilesystemScreen::new();
        let mut st = state();
        assert!(st.config.persist_fs.is_none());
        assert_eq!(scr.handle_key(key(KeyCode::Char('n')), &mut st), Nav::Next);
        assert_eq!(st.config.persist_fs, Some(Fs::Ext4));
    }

    #[test]
    fn back_and_quit() {
        let mut scr = FilesystemScreen::new();
        let mut st = state();
        assert_eq!(scr.handle_key(key(KeyCode::Char('b')), &mut st), Nav::Back);
        assert_eq!(scr.handle_key(key(KeyCode::Char('q')), &mut st), Nav::Quit);
    }
}
