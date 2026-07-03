/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
pub mod disks;
pub mod filesystem;
pub mod io;
pub mod overview;
pub mod persist;
pub mod screen;
pub mod state;
pub mod theme;
pub mod util;

use anyhow::Result;
use ratatui::crossterm::cursor::{Hide, Show};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Alignment, Rect};
use ratatui::prelude::CrosstermBackend;
use ratatui::text::Line;
use ratatui::widgets::{Block, BorderType, Borders, Clear, Padding};
use ratatui::{Terminal, TerminalOptions, Viewport};
use std::fs::OpenOptions;
use std::io::{stdout, Write};
use std::os::unix::io::AsRawFd;

use crate::config::InstallConfig;
use crate::disk::Disk;
use crate::plan::HardwareFacts;
use screen::{Nav, Screen};
pub use state::{Outcome, WizardState};
use util::{centered_rect, step_title};

/// A terminal we render the wizard to. Boxed writer so the primary (stdout on
/// tty2) and the serial devices share one type.
type WizTerminal = Terminal<CrosstermBackend<Box<dyn Write + Send>>>;

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

/// Restore the primary terminal (tty2): leave raw mode and the alternate screen,
/// show the cursor. Idempotent, so it is safe from both the panic hook and the
/// RAII guard. Serial devices restore their own termios via their guards.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(stdout(), LeaveAlternateScreen, Show);
}

/// RAII guard: restores the primary terminal on drop (normal exit, error, panic).
struct TermGuard;
impl Drop for TermGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Render the current screen as a centered, bordered dialog over a blue
/// backdrop, to every attached terminal. The driver owns all the chrome
/// (backdrop, popup frame, title); screens draw only their content into the
/// dialog's inner area.
fn draw_all(
    terminals: &mut [WizTerminal],
    screens: &mut [Box<dyn Screen>],
    index: usize,
    state: &WizardState,
) -> Result<()> {
    let title = step_title(index, screens.len(), screens[index].title());
    for t in terminals.iter_mut() {
        t.draw(|f| {
            let area = f.area();
            // Blue backdrop, then a centered popup with the backdrop showing
            // around it.
            f.render_widget(Block::default().style(theme::backdrop()), area);
            let dialog = centered_rect(area, 76, 22);
            f.render_widget(Clear, dialog);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme::border())
                .style(theme::dialog())
                .padding(Padding::new(2, 2, 1, 0))
                .title(Line::styled(format!(" {title} "), theme::title()))
                .title_alignment(Alignment::Center);
            let inner = block.inner(dialog);
            f.render_widget(block, dialog);
            screens[index].render(f, inner, state);
        })?;
    }
    Ok(())
}

/// Run the wizard, rendering to the primary terminal (stdout — tty2 when launched
/// via `openvt`) and to every device in `serial_consoles` simultaneously, with
/// input merged from all of them. `serial_consoles` are device paths (e.g.
/// `/dev/ttyS0`), never `/dev/console`.
pub fn run(
    disks: Vec<Disk>,
    boot: Option<String>,
    config: InstallConfig,
    hw: HardwareFacts,
    serial_consoles: &[String],
) -> Result<Outcome> {
    enable_raw_mode()?;
    // Construct the restore guard immediately, BEFORE entering the alternate
    // screen: if EnterAlternateScreen fails, Drop still disables raw mode so we
    // never leave the terminal wedged.
    let _guard = TermGuard;
    // Restore-first panic hook so a panic message survives the alternate screen.
    // (Short-lived CLI, so leaving the hook installed on normal exit is fine.)
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        prev_hook(info);
    }));
    execute!(stdout(), EnterAlternateScreen, Hide)?;

    // Primary terminal: stdout, which is tty2 when launched under `openvt`.
    let mut terminals: Vec<WizTerminal> =
        vec![Terminal::new(CrosstermBackend::new(Box::new(stdout()) as Box<dyn Write + Send>))?];
    let mut input_fds = vec![libc::STDIN_FILENO];
    // Kept alive so their fds (used for input polling) stay open until run exits.
    let mut serial_readers: Vec<std::fs::File> = Vec::new();
    // Declared AFTER terminals so, on unwind, guards drop (restore termios)
    // while the device fds are still open.
    let mut termios_guards: Vec<io::TermiosGuard> = Vec::new();

    // Don't drive a serial console that is already the primary terminal (the
    // headless case, where stdout is itself the serial line) — that would render
    // it twice.
    let primary = io::primary_tty_path();

    for path in serial_consoles {
        if primary.as_deref() == Some(path.as_str()) {
            continue;
        }
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => {
                let fd = file.as_raw_fd();
                // Best-effort raw mode + a sane size; a serial line that can't be
                // configured still gets a terminal, just cooked/80x24.
                if let Ok(g) = unsafe { io::TermiosGuard::make_raw(fd) } {
                    termios_guards.push(g);
                }
                let (cols, rows) = unsafe { io::ensure_winsize(fd) };
                match file.try_clone() {
                    Ok(mut wf) => {
                        let _ = execute!(wf, EnterAlternateScreen, Hide);
                        let backend = CrosstermBackend::new(Box::new(wf) as Box<dyn Write + Send>);
                        // Serial size can't be read via crossterm (it queries the
                        // controlling tty), so pin a fixed viewport to this device.
                        let opts = TerminalOptions {
                            viewport: Viewport::Fixed(Rect::new(0, 0, cols, rows)),
                        };
                        if let Ok(t) = Terminal::with_options(backend, opts) {
                            terminals.push(t);
                            input_fds.push(fd);
                            serial_readers.push(file);
                        }
                    }
                    Err(e) => eprintln!("[tui] cannot clone {path}: {e}"),
                }
            }
            Err(e) => eprintln!("[tui] cannot open console {path}: {e}"),
        }
    }

    let mut state = WizardState { disks, boot, config, hw };
    let mut screens: Vec<Box<dyn Screen>> = vec![
        Box::new(disks::DisksScreen::new()),
        Box::new(filesystem::FilesystemScreen::new()),
        Box::new(persist::PersistScreen::new()),
        Box::new(overview::OverviewScreen::new()),
    ];
    let mut index = 0usize;
    screens[index].on_enter(&mut state);

    let reader = io::InputReader::spawn(input_fds);

    draw_all(&mut terminals, &mut screens, index, &state)?;
    let outcome = loop {
        let key = match reader.rx.recv() {
            Ok(k) => k,
            Err(_) => break Outcome::Cancelled, // all input devices gone
        };
        let nav = screens[index].handle_key(key, &mut state);
        match apply_nav(nav, index, screens.len()) {
            NavResult::Continue(i) => {
                if i != index {
                    index = i;
                    screens[index].on_enter(&mut state);
                }
            }
            NavResult::Finish => break Outcome::Completed(state.config.clone()),
            NavResult::Cancel => break Outcome::Cancelled,
        }
        draw_all(&mut terminals, &mut screens, index, &state)?;
    };

    // Leave the alternate screen on the serial terminals explicitly (the primary
    // is handled by TermGuard on drop).
    for t in terminals.iter_mut().skip(1) {
        let _ = execute!(t.backend_mut(), LeaveAlternateScreen, Show);
    }
    Ok(outcome)
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
