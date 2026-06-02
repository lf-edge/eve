// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::model::model::Model;
use crate::ui::action::Action;
use crate::ui::activity::Activity;
use crate::ui::traits::IntoRatatuiStyle;
use std::cmp;
use std::rc::Rc;

use crate::events::Event;
use crate::traits::{IEventHandler, IPresenter, IWindow};
use crossterm::event::{KeyCode, KeyEvent};
use log::trace;
use ratatui::prelude::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState};
use ratatui::Frame;
use rmesg::entry::{Entry, LogLevel};

#[derive(Debug, Default)]
pub struct DmesgViewer {
    _mode: DmsgMode,
    buffer_index: usize,
    lines_per_page: u16,
    buffer_len: usize,
}

#[derive(Default, Debug)]
enum DmsgMode {
    #[default]
    Follow,
    Scroll,
}

impl DmesgViewer {
    pub fn new() -> Self {
        DmesgViewer::default()
    }

    fn switch_to_scroll_mode(&mut self) {
        self._mode = DmsgMode::Scroll;
    }

    pub fn handle_keys_following(&mut self, key: KeyEvent) -> Option<Activity> {
        match key.code {
            KeyCode::Down
            | KeyCode::Up
            | KeyCode::PageDown
            | KeyCode::PageUp
            | KeyCode::Home
            | KeyCode::End
            | KeyCode::Char(' ') => {
                self.switch_to_scroll_mode();
                self.handle_keys_scroll(key)
            }
            _ => None,
        }
    }

    pub fn handle_keys_scroll(&mut self, key: KeyEvent) -> Option<Activity> {
        match key.code {
            KeyCode::Down => {
                self.buffer_index = cmp::min(
                    self.buffer_index + 1 as usize,
                    self.buffer_len - self.lines_per_page as usize,
                );
            }
            KeyCode::Up => {
                self.buffer_index = self.buffer_index.saturating_sub(1);
            }
            KeyCode::PageDown => {
                self.buffer_index = cmp::min(
                    self.buffer_index + self.lines_per_page as usize,
                    self.buffer_len - self.lines_per_page as usize,
                );
            }
            KeyCode::PageUp => {
                self.buffer_index = self
                    .buffer_index
                    .saturating_sub(self.lines_per_page as usize);
            }
            KeyCode::End => {
                self.buffer_index = self.buffer_len - self.lines_per_page as usize;
            }
            KeyCode::Home => {
                self.buffer_index = 0;
            }
            KeyCode::Char(' ') => {
                self._mode = DmsgMode::Follow;
            }
            _ => return None,
        }
        Some(Activity::redraw())
    }
}

impl IntoRatatuiStyle for Option<LogLevel> {
    fn style(&self) -> Style {
        match self {
            Some(LogLevel::Emergency) => Style::default().fg(ratatui::style::Color::Red),
            Some(LogLevel::Alert) => Style::default().fg(ratatui::style::Color::Red),
            Some(LogLevel::Critical) => Style::default().fg(ratatui::style::Color::Red),
            Some(LogLevel::Error) => Style::default().fg(ratatui::style::Color::Red),
            Some(LogLevel::Warning) => Style::default().fg(ratatui::style::Color::Yellow),
            Some(LogLevel::Notice) => Style::default().fg(ratatui::style::Color::Yellow),
            Some(LogLevel::Info) => Style::default(),
            Some(LogLevel::Debug) => Style::default().fg(ratatui::style::Color::Blue),
            None => Style::default(),
        }
    }
}

impl IPresenter for DmesgViewer {
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, model: &Rc<Model>, _focused: bool) {
        let page_size = area.height as usize;
        self.buffer_len = model.borrow().dmesg.len();
        self.lines_per_page = area.height;
        trace!(
            "Rendering dmesg: {:?}, page={} log_size={}",
            area,
            page_size,
            model.borrow().dmesg.len()
        );

        let dmesg = &model.borrow().dmesg;
        // get last page_size entries from or the whole buffer if it's smaller
        let content: Vec<&Entry> = match self._mode {
            DmsgMode::Follow => {
                self.buffer_index = self.buffer_len.saturating_sub(page_size);
                dmesg.iter().rev().take(page_size).rev().collect()
            }
            DmsgMode::Scroll => dmesg
                .iter()
                .skip(self.buffer_index)
                .take(page_size)
                .collect(),
        };

        let lines: Vec<Line> = content
            .iter()
            .map(|entry| {
                Line::from(entry.timestamp_from_system_start.map_or_else(
                    || Span::styled(format!("{:4}{}\n", "", entry.message), entry.level.style()),
                    |ts| {
                        Span::styled(
                            format!("[{:.6}] {}\n", ts.as_secs_f32(), entry.message),
                            entry.level.style(),
                        )
                    },
                ))
            })
            .collect();

        // render vertical scrollbar on the right
        let mut scrollbar_state = ScrollbarState::new(self.buffer_len).position(self.buffer_index);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));

        frame.render_widget(Paragraph::new(lines), *area);

        frame.render_stateful_widget(scrollbar, *area, &mut scrollbar_state);
    }
}

impl IWindow for DmesgViewer {}
impl IEventHandler for DmesgViewer {
    fn handle_event(&mut self, event: crate::events::Event) -> Option<Action> {
        let activity = match event {
            Event::Tick | Event::TerminalResize(_, _) => None, // we want this to trigger a rerender, but that will happen even if we do nothing here
            Event::Key(key) => match self._mode {
                DmsgMode::Follow => self.handle_keys_following(key),
                DmsgMode::Scroll => self.handle_keys_scroll(key),
            },
        }?;
        match activity {
            Activity::Action(action) => Some(Action::new("something".to_string(), action)),
            Activity::Event(_) => None,
        }
    }
}
