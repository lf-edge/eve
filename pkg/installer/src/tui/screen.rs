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
    /// Short screen name, shown by the driver in the step indicator
    /// ("Step 2/4 · <title>"). Screens render their body without repeating it.
    fn title(&self) -> &str;
    fn render(&mut self, f: &mut Frame, area: Rect, state: &WizardState);
    fn handle_key(&mut self, key: KeyEvent, state: &mut WizardState) -> Nav;
    /// Called by the driver when navigation lands on this screen (including the
    /// first screen at startup). Lets a screen sync its cursor to the current
    /// config and normalize/seed any state it owns. Default: no-op.
    fn on_enter(&mut self, _state: &mut WizardState) {}
}
