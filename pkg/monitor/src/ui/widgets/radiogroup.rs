// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Radio-group widget; intended UI API not yet instantiated by a page.
#![allow(dead_code)]

use crossterm::event::{KeyCode, KeyEvent};
use log::{info, trace};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Paragraph, Widget},
    Frame,
};

use crate::{
    traits::{IElementEventHandler, IWidget, IWidgetPresenter},
    ui::action::UiActions,
};

pub struct RadioGroupElement {
    pub labels: Vec<String>,
    pub selected: usize,
    pub focused: usize,
    pub title: String,
}

impl IWidget for RadioGroupElement {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl RadioGroupElement {
    pub fn new<S: Into<String>, P: Into<String>>(labels: Vec<S>, title: P) -> Self {
        Self {
            labels: labels.into_iter().map(|s| s.into()).collect(),
            selected: 0,
            focused: 0,
            title: title.into(),
        }
    }
    fn create_status_update(&self) -> UiActions {
        info!("RadioGroupElement: selected: {}", self.selected);
        UiActions::RadioGroup {
            selected: self.selected,
        }
    }
}

impl IWidgetPresenter for RadioGroupElement {
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, focused: bool) {
        //trace!("rendering: RadioGroupElement {:#?}", &self);
        let style = if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };

        let block = Block::default()
            .title(self.title.clone())
            .borders(Borders::ALL)
            .border_style(style);
        let inner = block.inner(*area);
        (&block).render(*area, frame.buffer_mut());
        // create vertical layout for radio buttons
        let constraints = self.labels.iter().map(|_| Constraint::Length(1));
        let buttons_area = Layout::vertical(constraints).split(inner);

        let selected_style = Modifier::REVERSED;
        let normal_style = Style::default().fg(Color::White);

        // render paragraphs for each radio button
        for (i, label) in self.labels.iter().enumerate() {
            // format the button label <text> (selected)
            let mut style = normal_style;
            let label = if self.selected == i {
                format!("{} (*)", label)
            } else {
                format!("{} ( )", label)
            };

            if self.focused == i && focused {
                style = style.add_modifier(selected_style);
            }

            let p = Paragraph::new(label).style(style);
            (&p).render(buttons_area[i], frame.buffer_mut());
        }
    }
}

impl IElementEventHandler for RadioGroupElement {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<UiActions> {
        trace!("handle_key_event: RadioGroupView {}", &self.title);
        match key.code {
            KeyCode::Up => {
                self.focused = self.focused.saturating_sub(1);
                Some(UiActions::Redraw)
            }
            KeyCode::Down => {
                self.focused = (self.focused + 1).min(self.labels.len() - 1);
                Some(UiActions::Redraw)
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.selected = self.focused;
                Some(self.create_status_update())
            }
            _ => None,
        }
    }
}
