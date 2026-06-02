// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use crossterm::{
    cursor, execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, is_raw_mode_enabled, Clear, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};

use std::{
    fs::{self, File},
    ops::{Deref, DerefMut},
};

use ratatui::{backend::CrosstermBackend, Terminal};

#[derive(Debug)]
pub struct TerminalWrapper {
    terminal: Terminal<CrosstermBackend<File>>,
}

impl TerminalWrapper {
    fn tty_fd() -> Result<File> {
        Ok(fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")?)
    }

    fn init_terminal(file: File) -> Result<Terminal<CrosstermBackend<File>>> {
        println!("Initializing terminal");
        // No stdout after this point
        execute!(&file, EnterAlternateScreen, cursor::Hide)?;
        enable_raw_mode()?;
        let mut terminal = Terminal::new(CrosstermBackend::new(file))?;
        terminal.clear()?;
        Ok(terminal)
    }

    pub fn open_terminal() -> Result<Self> {
        let file = Self::tty_fd()?;
        let terminal = Self::init_terminal(file)?;
        Ok(Self { terminal })
    }

    pub fn close_terminal() -> Result<()> {
        if is_raw_mode_enabled()? {
            let mut file = Self::tty_fd()?;
            execute!(file, LeaveAlternateScreen, cursor::Show)?;
            execute!(file, Clear(crossterm::terminal::ClearType::All))?;
            disable_raw_mode()?;
        }
        // No stdout before this point
        println!("Terminal should be now closed");
        Ok(())
    }

    pub fn get_stream() -> crossterm::event::EventStream {
        crossterm::event::EventStream::new()
    }
}

impl Drop for TerminalWrapper {
    fn drop(&mut self) {
        let _ = self.terminal.clear();
        let _ = Self::close_terminal();
    }
}

impl Deref for TerminalWrapper {
    type Target = Terminal<CrosstermBackend<File>>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

impl DerefMut for TerminalWrapper {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}
