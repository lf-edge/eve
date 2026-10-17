/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
//! Shared colour theme for the installer wizard: a dark dialog on a blue
//! backdrop, classic-installer style. Kept in one place so every screen looks
//! the same and the palette is easy to tweak. Colours are the 16 named ANSI
//! colours so they render on a plain Linux VT and over serial.

use ratatui::style::{Color, Modifier, Style};

/// Full-screen background behind the dialog.
pub fn backdrop() -> Style {
    Style::default().bg(Color::Blue)
}

/// The dialog body (and default text inside it).
pub fn dialog() -> Style {
    Style::default().bg(Color::Black).fg(Color::White)
}

/// Dialog border lines.
pub fn border() -> Style {
    Style::default().bg(Color::Black).fg(Color::White)
}

/// Dialog title text (centered in the top border).
pub fn title() -> Style {
    Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD)
}

/// The row/option under the cursor.
pub fn selected() -> Style {
    Style::default().bg(Color::Cyan).fg(Color::Black).add_modifier(Modifier::BOLD)
}

/// Footer key hints.
pub fn hint() -> Style {
    Style::default().bg(Color::Black).fg(Color::Gray)
}

/// Dimmed / unavailable rows (e.g. the boot disk, or raid rows under ext4).
pub fn disabled() -> Style {
    Style::default().bg(Color::Black).fg(Color::DarkGray)
}

/// Non-fatal advisories on the Overview screen.
pub fn advisory() -> Style {
    Style::default().bg(Color::Black).fg(Color::Yellow)
}

/// A blocking rejection / incomplete-config message.
pub fn error() -> Style {
    Style::default().bg(Color::Black).fg(Color::Red).add_modifier(Modifier::BOLD)
}
