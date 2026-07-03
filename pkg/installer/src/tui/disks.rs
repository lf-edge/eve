/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::Frame;

use super::screen::{Nav, Screen};
use super::state::WizardState;

/// Minimal placeholder: renders nothing and always quits. Task 4 fleshes
/// this out into the real disk-selection screen.
pub struct DisksScreen {}

impl DisksScreen {
    pub fn new() -> Self {
        DisksScreen {}
    }
}

impl Default for DisksScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen for DisksScreen {
    fn render(&mut self, _f: &mut Frame, _area: Rect, _state: &WizardState) {}
    fn handle_key(&mut self, _key: KeyEvent, _state: &mut WizardState) -> Nav {
        Nav::Quit
    }
}
