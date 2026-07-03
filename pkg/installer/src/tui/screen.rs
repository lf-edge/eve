/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
use ratatui::crossterm::event::KeyEvent;
use ratatui::layout::Rect;
use ratatui::Frame;

use super::state::WizardState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nav {
    Stay,
    Next,
    Back,
    Quit,
}

pub trait Screen {
    fn render(&mut self, f: &mut Frame, area: Rect, state: &WizardState);
    fn handle_key(&mut self, key: KeyEvent, state: &mut WizardState) -> Nav;
}
