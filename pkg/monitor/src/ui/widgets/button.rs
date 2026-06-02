// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crossterm::event::{KeyCode, KeyEvent};
use log::{info, trace};
use ratatui::{
    layout::Alignment,
    prelude::Rect,
    style::{Color, Style},
    widgets::{Block, BorderType, Borders, Paragraph},
};

use crate::{
    traits::{IElementEventHandler, IWidget, IWidgetPresenter},
    ui::action::UiActions,
};

use ratatui::widgets::WidgetRef;

//pub type ButtonElement<A> = Element<ButtonWidgetState<A>>;
pub struct ButtonElement {
    label: String,
    pushed: bool,
}

impl ButtonElement {
    pub fn new<S: Into<String>>(label: S) -> Self {
        Self {
            label: label.into(),
            pushed: false,
        }
    }
    fn is_pushed(&self) -> bool {
        self.pushed
    }
}

impl IWidgetPresenter for ButtonElement {
    fn render(&mut self, area: &Rect, frame: &mut ratatui::Frame<'_>, focused: bool) {
        trace!(
            "Rendering button: {:?}: focused: {}",
            self.label.as_str(),
            focused
        );
        // set border style based on focus
        let border_style = if focused {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::Gray)
        };

        // set border type based on push state
        let border_type = if focused {
            //FIXME: need new Font
            //BorderType::Thick
            BorderType::Double
        } else {
            //FIXME: need new Font
            //BorderType::Rounded
            BorderType::Plain
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(border_type)
            .border_style(border_style)
            .style(Style::default().bg(Color::Black));

        let button = if self.is_pushed() {
            Paragraph::new(self.label.as_str())
                .style(Style::default().fg(Color::Black).bg(Color::White))
                .alignment(Alignment::Center)
                .block(block)
        } else {
            Paragraph::new(self.label.as_str())
                .style(Style::default().fg(Color::White).bg(Color::Black))
                .alignment(Alignment::Center)
                .block(block)
        };
        button.render_ref(*area, frame.buffer_mut());
    }
}

impl IElementEventHandler for ButtonElement {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<UiActions> {
        info!("Handling key event: {:?}", key);
        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => {
                if key.kind == crossterm::event::KeyEventKind::Press {
                    self.pushed = true;
                    info!("Button pushed");

                    return Some(UiActions::ButtonClicked(self.label.clone()));

                // TODO: Release event never comes if crossterm::event::PushKeyboardEnhancementFlags
                // is not enabled.
                } else if key.kind == crossterm::event::KeyEventKind::Release {
                    info!("Button released");
                    self.pushed = false;
                    return None;
                } else {
                    return None;
                }
            }
            _ => None,
        }
    }
}

impl IWidget for ButtonElement {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
