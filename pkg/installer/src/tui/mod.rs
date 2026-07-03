/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
#![allow(dead_code)] // wizard scaffold; not wired into the binary until a later task drives it from main.rs.
pub mod disks;
pub mod screen;
pub mod state;
pub mod util;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::CrosstermBackend;
use ratatui::Terminal;
use std::io::{stdout, Stdout};

use crate::disk::Disk;
use screen::{Nav, Screen};
pub use state::{Outcome, WizardState};

/// Pure wizard-navigation step. Returned to the driver to advance/finish/cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavResult {
    Continue(usize),
    Finish,
    Cancel,
}

pub fn apply_nav(nav: Nav, index: usize, n_screens: usize) -> NavResult {
    match nav {
        Nav::Stay => NavResult::Continue(index),
        Nav::Back => NavResult::Continue(index.saturating_sub(1)),
        Nav::Quit => NavResult::Cancel,
        Nav::Next => {
            if index + 1 < n_screens {
                NavResult::Continue(index + 1)
            } else {
                NavResult::Finish
            }
        }
    }
}

/// RAII guard: restores the terminal on drop (covers normal exit, error, and
/// panic unwinding).
struct TermGuard;
impl Drop for TermGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen);
    }
}

pub fn run(disks: Vec<Disk>, boot: Option<String>) -> Result<Outcome> {
    enable_raw_mode()?;
    execute!(stdout(), EnterAlternateScreen)?;
    let _guard = TermGuard;
    let mut terminal: Terminal<CrosstermBackend<Stdout>> =
        Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut state = WizardState {
        disks,
        boot,
        config: crate::config::InstallConfig::default(),
    };
    let mut screens: Vec<Box<dyn Screen>> = vec![Box::new(disks::DisksScreen::new())];
    let mut index = 0usize;

    loop {
        terminal.draw(|f| screens[index].render(f, f.area(), &state))?;
        if let Event::Key(key) = event::read()? {
            let nav = screens[index].handle_key(key, &mut state);
            match apply_nav(nav, index, screens.len()) {
                NavResult::Continue(i) => index = i,
                NavResult::Finish => return Ok(Outcome::Completed(state.config)),
                NavResult::Cancel => return Ok(Outcome::Cancelled),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn apply_nav_transitions() {
        assert_eq!(apply_nav(Nav::Stay, 0, 3), NavResult::Continue(0));
        assert_eq!(apply_nav(Nav::Back, 0, 3), NavResult::Continue(0)); // no-op at first
        assert_eq!(apply_nav(Nav::Back, 2, 3), NavResult::Continue(1));
        assert_eq!(apply_nav(Nav::Next, 0, 3), NavResult::Continue(1));
        assert_eq!(apply_nav(Nav::Next, 2, 3), NavResult::Finish); // last screen
        assert_eq!(apply_nav(Nav::Quit, 1, 3), NavResult::Cancel);
    }
}
