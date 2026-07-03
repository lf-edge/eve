/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
pub mod disks;
pub mod filesystem;
pub mod overview;
pub mod persist;
pub mod screen;
pub mod state;
pub mod util;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Layout};
use ratatui::prelude::CrosstermBackend;
use ratatui::style::{Modifier, Style};
use ratatui::widgets::Paragraph;
use ratatui::Terminal;
use std::io::{stdout, Stdout};

use crate::config::InstallConfig;
use crate::disk::Disk;
use crate::plan::HardwareFacts;
use screen::{Nav, Screen};
pub use state::{Outcome, WizardState};
use util::step_title;

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

/// Restore the terminal: leave raw mode and the alternate screen. Idempotent, so
/// it is safe to run from both the panic hook and the RAII guard.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen);
}

/// RAII guard: restores the terminal on drop (covers normal exit, error, and
/// panic unwinding).
struct TermGuard;
impl Drop for TermGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

pub fn run(
    disks: Vec<Disk>,
    boot: Option<String>,
    config: InstallConfig,
    hw: HardwareFacts,
) -> Result<Outcome> {
    enable_raw_mode()?;
    // Construct the restore guard immediately, BEFORE entering the alternate
    // screen: if EnterAlternateScreen fails, Drop still disables raw mode so we
    // never leave the terminal wedged.
    let _guard = TermGuard;
    // Restore-first panic hook: a panic inside the alternate screen would
    // otherwise print its message where the user can't see it. Restore the
    // terminal, then chain the previous hook so the message lands on a normal
    // screen. (This is a short-lived CLI, so leaving the hook installed on the
    // normal-exit path is fine.)
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        prev_hook(info);
    }));
    execute!(stdout(), EnterAlternateScreen)?;
    let mut terminal: Terminal<CrosstermBackend<Stdout>> =
        Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut state = WizardState { disks, boot, config, hw };
    let mut screens: Vec<Box<dyn Screen>> = vec![
        Box::new(disks::DisksScreen::new()),
        Box::new(filesystem::FilesystemScreen::new()),
        Box::new(persist::PersistScreen::new()),
        Box::new(overview::OverviewScreen::new()),
    ];
    let mut index = 0usize;
    screens[index].on_enter(&mut state);

    loop {
        terminal.draw(|f| {
            // Split off a one-line step indicator above the current screen.
            let chunks = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(f.area());
            let header = step_title(index, screens.len(), screens[index].title());
            f.render_widget(
                Paragraph::new(header).style(Style::default().add_modifier(Modifier::BOLD)),
                chunks[0],
            );
            screens[index].render(f, chunks[1], &state);
        })?;
        if let Event::Key(key) = event::read()? {
            let nav = screens[index].handle_key(key, &mut state);
            match apply_nav(nav, index, screens.len()) {
                NavResult::Continue(i) => {
                    if i != index {
                        index = i;
                        screens[index].on_enter(&mut state);
                    }
                }
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
