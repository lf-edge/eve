// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Status-bar widget; the tips field/setter are intended API not yet wired.
#![allow(dead_code)]

use ratatui::{
    layout::{Constraint, Flex, Layout, Margin},
    style::{Color, Style},
    widgets::{Block, BorderType, Borders, WidgetRef},
};

use super::{widgets::label::LabelElement, window::Window};

#[derive(Default)]
pub struct StatusBarState {
    tips: Option<String>,
}


impl StatusBarState {
    pub fn set_tips(&mut self, tips: Option<String>) {
        self.tips = tips;
    }
}

pub fn create_status_bar() -> Window<StatusBarState> {
    let clock = LabelElement::new("Clock").on_tick(|label| {
        let now = chrono::Local::now();
        let time = now.format("%H:%M:%S").to_string();
        label.set_text(time);
    });

    let tips = LabelElement::new("");

    let w = Window::builder("StatusBar")
        .with_state(StatusBarState::default())
        .widget("Clock", clock)
        .widget("Tips", tips)
        .with_layout(|w, rect, _model| {
            let inner_rect = rect.inner(Margin {
                horizontal: 1,
                vertical: 1,
            });

            let layout = Layout::horizontal([Constraint::Fill(1), Constraint::Length(8)])
                .flex(Flex::End)
                .split(inner_rect);
            w.update_layout("Clock", layout[1]);
            w.update_layout("Tips", layout[0]);
        })
        .with_render(|_w, rect, frame, _model| {
            let model = _model.borrow();

            // FIXME: implement without downcast
            let tips = _w.get_widget_mut("Tips").unwrap();
            let label: &mut LabelElement =
                tips.as_any_mut().downcast_mut::<LabelElement>().unwrap();
            label.set_text(model.status_bar_tips.clone().unwrap_or_default());

            let blk = Block::new()
                //.border_type(BorderType::Rounded)
                //FIXME: need new Font
                .border_type(BorderType::Plain)
                .borders(Borders::ALL)
                .style(Style::default().bg(Color::Black));

            blk.render_ref(*rect, frame.buffer_mut());
        })
        .build();

    w.unwrap()
}
