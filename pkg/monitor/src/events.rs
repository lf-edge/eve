// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crossterm::event::KeyEvent;

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    Key(KeyEvent),
    Tick,
    TerminalResize(u16, u16),
}
