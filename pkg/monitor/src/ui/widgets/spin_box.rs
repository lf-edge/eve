// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Spin-box widget API; the Vertical layout and builder methods are intended
// surface not yet exercised by a caller.
#![allow(dead_code)]

use log::info;
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Paragraph, WidgetRef},
    Frame,
};

use crate::{
    traits::{IElementEventHandler, IWidget, IWidgetPresenter},
    ui::action::UiActions,
};
#[derive(PartialEq)]
pub enum SpinBoxLayout {
    Horizontal,
    Vertical,
}

pub struct SpinBoxElement {
    items: Vec<String>,
    selected: usize,
    // cache maximum length of items
    max_len: usize,
    layout: SpinBoxLayout,
    size_hint: Option<usize>,
}

impl IWidget for SpinBoxElement {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl SpinBoxElement {
    pub fn new<S: Into<String>>(items: Vec<S>) -> Self {
        let items: Vec<String> = items.into_iter().map(|s| s.into()).collect();
        let max_len = items.iter().map(|s| s.len()).max().unwrap_or_default();
        Self {
            items,
            selected: 0,
            max_len,
            layout: SpinBoxLayout::Horizontal,
            size_hint: None,
        }
    }
    pub fn selected(mut self, index: usize) -> Self {
        self.selected = index;
        self
    }

    pub fn layout(mut self, layout: SpinBoxLayout) -> Self {
        self.layout = layout;
        self
    }

    pub fn size_hint(mut self, size_hint: usize) -> Self {
        self.size_hint = Some(size_hint);
        self
    }

    fn create_status_update(&self) -> UiActions {
        info!("SpinBoxElement: selected: {}", self.selected);
        UiActions::SpinBox {
            selected: self.selected,
        }
    }

    fn on_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        } else {
            self.selected = self.items.len() - 1;
        }
    }

    fn on_down(&mut self) {
        if self.selected < self.items.len() - 1 {
            self.selected += 1;
        } else {
            self.selected = 0;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_spinner(
        &mut self,
        up_arrow_rect: Rect,
        down_arrow_rect: Rect,
        text_rect: Rect,
        up_arrow: char,
        down_arrow: char,
        style: Style,
        buf: &mut Buffer,
    ) {
        let text = self.items[self.selected].clone();
        let up = Paragraph::new(up_arrow.to_string())
            .alignment(Alignment::Center)
            .style(style.bg(Color::Gray).fg(Color::DarkGray));
        let down = Paragraph::new(down_arrow.to_string())
            .alignment(Alignment::Center)
            .style(style.bg(Color::Gray).fg(Color::DarkGray));
        let text = Paragraph::new(text)
            .alignment(Alignment::Center)
            .style(style);
        //TODO: I separate regions to be able to draw "pressed" state on tick
        up.render_ref(up_arrow_rect, buf);
        down.render_ref(down_arrow_rect, buf);
        text.render_ref(text_rect, buf);
    }
}

impl IElementEventHandler for SpinBoxElement {
    fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) -> Option<UiActions> {
        if self.layout == SpinBoxLayout::Horizontal {
            match key {
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Left,
                    ..
                } => {
                    self.on_up();
                    Some(self.create_status_update())
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Right,
                    ..
                } => {
                    self.on_down();
                    Some(self.create_status_update())
                }
                _ => None,
            }
        } else {
            match key {
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Up,
                    ..
                } => {
                    self.on_up();
                    Some(self.create_status_update())
                }
                crossterm::event::KeyEvent {
                    code: crossterm::event::KeyCode::Down,
                    ..
                } => {
                    self.on_down();
                    Some(self.create_status_update())
                }
                _ => None,
            }
        }
    }
}

impl IWidgetPresenter for SpinBoxElement {
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, focused: bool) {
        let style = if focused {
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::REVERSED)
        } else {
            Style::default().fg(Color::White).bg(Color::DarkGray)
        };

        //render spinner as 'TEXT ▲▼'
        // or as '◄ TEXT ►'

        let max_size = self.size_hint.unwrap_or_default().max(self.max_len + 4); // +2 for margin +2 for arrows

        // shrink the area to the size of the spinner
        let area = Rect::new(area.x, area.y, max_size as u16, 1);

        // create 3 regions |◄| TEXT |►|
        if self.layout == SpinBoxLayout::Horizontal {
            let [left, text, right] = Layout::horizontal([
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
            ])
            .areas(area);
            self.draw_spinner(left, right, text, '◄', '►', style, frame.buffer_mut());
        } else {
            let [text, left, right] = Layout::horizontal([
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(1),
            ])
            .areas(area);
            self.draw_spinner(left, right, text, '▲', '▼', style, frame.buffer_mut());
        };
    }
}
