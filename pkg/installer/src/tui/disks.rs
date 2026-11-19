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

pub struct DisksScreen {
    cursor: usize, // index into the selectable (non-boot) disks
}

impl DisksScreen {
    pub fn new() -> Self {
        DisksScreen { cursor: 0 }
    }

    // Indices into state.disks that are selectable install targets (not the boot disk).
    fn selectable(&self, state: &WizardState) -> Vec<usize> {
        state
            .disks
            .iter()
            .enumerate()
            .filter(|(_, d)| state.boot.as_deref() != Some(d.name.as_str()))
            .map(|(i, _)| i)
            .collect()
    }
}

impl Default for DisksScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen for DisksScreen {
    fn title(&self) -> &str {
        "Select install disk"
    }

    fn on_enter(&mut self, state: &mut WizardState) {
        // Put the cursor on the already-selected (e.g. prefilled) install disk.
        let sel = self.selectable(state);
        if let Some(name) = state.config.install_disk.as_deref() {
            if let Some(pos) = sel.iter().position(|&i| state.disks[i].name == name) {
                self.cursor = pos;
            }
        }
    }

    fn render(&mut self, f: &mut Frame, area: Rect, state: &WizardState) {
        let sel = self.selectable(state);
        let cursor_disk = sel.get(self.cursor).copied();
        let mut lines: Vec<Line> = Vec::new();
        for (i, d) in state.disks.iter().enumerate() {
            let is_boot = state.boot.as_deref() == Some(d.name.as_str());
            let is_cursor = Some(i) == cursor_disk;
            let is_selected = state.config.install_disk.as_deref() == Some(d.name.as_str());
            let marker = if is_selected { "[x] " } else if is_cursor { " >  " } else { "    " };
            let mut label = format!(
                "{marker}{}  {}  {}  {}",
                d.name,
                human_size(d.size_bytes),
                d.model.as_deref().unwrap_or("-"),
                d.serial.as_deref().unwrap_or("-"),
            );
            if is_boot {
                label.push_str("  (boot)");
            }
            let style = if is_cursor {
                theme::selected()
            } else if is_boot {
                theme::disabled()
            } else {
                theme::dialog()
            };
            lines.push(Line::from(Span::styled(label, style)));
            for p in &d.partitions {
                lines.push(Line::from(Span::styled(
                    format!(
                        "      - {}  {}  {}  {}",
                        p.name,
                        human_size(p.size_bytes),
                        p.fstype.as_deref().unwrap_or("-"),
                        p.label.as_deref().unwrap_or("-"),
                    ),
                    theme::disabled(),
                )));
            }
        }
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "↑/↓ move · Enter select · n next · q quit",
            theme::hint(),
        ));
        let para = Paragraph::new(lines).style(theme::dialog());
        f.render_widget(para, area);
    }

    fn handle_key(&mut self, key: KeyEvent, state: &mut WizardState) -> Nav {
        let sel = self.selectable(state);
        match key.code {
            KeyCode::Up => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
                Nav::Stay
            }
            KeyCode::Down => {
                if self.cursor + 1 < sel.len() {
                    self.cursor += 1;
                }
                Nav::Stay
            }
            KeyCode::Enter => {
                if let Some(&di) = sel.get(self.cursor) {
                    state.config.install_disk = Some(state.disks[di].name.clone());
                }
                Nav::Stay
            }
            KeyCode::Char('n') | KeyCode::Right => {
                if state.config.install_disk.is_some() {
                    Nav::Next
                } else {
                    Nav::Stay
                }
            }
            KeyCode::Char('q') | KeyCode::Esc => Nav::Quit,
            _ => Nav::Stay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::InstallConfig;
    use crate::disk::{Disk, Partition};
    use crate::plan::HardwareFacts;
    use ratatui::crossterm::event::{KeyCode, KeyEvent};
    use ratatui::{backend::TestBackend, Terminal};

    fn hw() -> HardwareFacts {
        HardwareFacts { memory_gb: 8, eve_flavor: "kvm".into(), platform: "generic".into() }
    }

    fn disk(name: &str, size: u64, parts: Vec<Partition>) -> Disk {
        Disk { name: name.into(), path: format!("/dev/{name}"), kind: "disk".into(),
            size_bytes: size, transport: None, model: Some("MODEL".into()),
            serial: Some("SER".into()), read_only: false, virtual_dev: false, partitions: parts }
    }
    fn state() -> WizardState {
        let vda = disk("vda", 40_000_000_000, vec![Partition {
            name: "vda1".into(), path: "/dev/vda1".into(), size_bytes: 2_000_000_000,
            fstype: Some("vfat".into()), label: Some("EFI".into()), partlabel: Some("EFI System".into()) }]);
        let vdb = disk("vdb", 8_000_000_000, vec![]);
        WizardState { disks: vec![vda, vdb], boot: Some("vda".into()), config: InstallConfig::default(), hw: hw() }
    }
    fn key(c: KeyCode) -> KeyEvent { KeyEvent::from(c) }
    fn buf_text(t: &Terminal<TestBackend>) -> String {
        t.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn renders_disks_and_partitions_and_marks_boot() {
        let mut scr = DisksScreen::new();
        let st = state();
        let mut term = Terminal::new(TestBackend::new(100, 20)).unwrap();
        term.draw(|f| scr.render(f, f.area(), &st)).unwrap();
        let s = buf_text(&term);
        assert!(s.contains("vda"));
        assert!(s.contains("vdb"));
        assert!(s.contains("vda1"));      // partition shown
        assert!(s.contains("vfat"));      // partition fstype
        assert!(s.contains("boot"));      // boot disk marked
        assert!(s.contains("MODEL"));     // model column
    }

    #[test]
    fn cursor_skips_boot_and_enter_selects_then_next() {
        let mut scr = DisksScreen::new();
        let mut st = state();
        // only vdb is selectable (vda is boot); cursor starts on the first selectable
        assert_eq!(scr.handle_key(key(KeyCode::Enter), &mut st), Nav::Stay);
        assert_eq!(st.config.install_disk.as_deref(), Some("vdb"));
        assert_eq!(scr.handle_key(key(KeyCode::Char('n')), &mut st), Nav::Next);
    }

    #[test]
    fn next_before_selection_stays_quit_cancels() {
        let mut scr = DisksScreen::new();
        let mut st = state();
        assert_eq!(scr.handle_key(key(KeyCode::Char('n')), &mut st), Nav::Stay); // nothing selected
        assert_eq!(scr.handle_key(key(KeyCode::Char('q')), &mut st), Nav::Quit);
    }
}
