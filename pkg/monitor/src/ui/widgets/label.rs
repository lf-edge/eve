// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{borrow::BorrowMut, fmt::Debug, rc::Rc};

use log::trace;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    widgets::{Paragraph, WidgetRef},
    Frame,
};

use crate::{
    traits::{IElementEventHandler, IWidget, IWidgetPresenter},
    ui::activity::Activity,
};

pub struct LabelElement {
    text: String,
    #[allow(clippy::type_complexity)]
    on_tick: Option<Rc<dyn Fn(&mut LabelElement)>>,
    state_updated: bool,
}

impl Debug for LabelElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabelElement")
            .field("text", &self.text)
            .finish()
    }
}

impl LabelElement {
    pub fn new<S: Into<String>>(text: S) -> Self {
        Self {
            text: text.into(),
            on_tick: None,
            state_updated: false,
        }
    }
    pub fn on_tick<F: Fn(&mut LabelElement) + 'static>(mut self, f: F) -> Self {
        self.on_tick = Some(Rc::new(f));
        self
    }

    pub fn set_text<S: Into<String>>(&mut self, text: S) {
        let new_text = text.into();
        if new_text != self.text {
            self.text = new_text;
            self.state_updated = true;
        }
    }
}

impl IWidgetPresenter for LabelElement {
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, _focused: bool) {
        let text = self.text.clone();
        trace!("LabelElement::render: {}", text);
        let p = Paragraph::new(text)
            .alignment(Alignment::Left)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .style(Style::default().fg(Color::White));
        p.render_ref(*area, frame.buffer_mut());
    }

    fn can_focus(&self) -> bool {
        false
    }
}

impl IElementEventHandler for LabelElement {
    fn handle_tick(&mut self) -> Option<crate::ui::activity::Activity> {
        trace!("LabelElement::handle_tick");
        self.state_updated = false;
        if let Some(on_tick) = self.on_tick.borrow_mut() {
            let on_tick = on_tick.clone();
            on_tick(self);
            if self.state_updated {
                return Some(Activity::redraw());
            }
        }
        None
    }
}
impl IWidget for LabelElement {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
