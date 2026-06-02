// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Generic dialog widget; part of the intended UI API even though no page
// currently instantiates it.
#![allow(dead_code)]

use std::rc::Rc;

use crate::events;
use crate::model::model::Model;
use crate::traits::IElementEventHandler;
use log::debug;
use ratatui::widgets::Clear;
use ratatui::widgets::Paragraph;

use crossterm::event::KeyEvent;
use log::{info, trace};
use ratatui::{
    layout::{self, Constraint, Flex, Rect},
    style::{Color, Style},
    widgets::{Block, BorderType, Borders, Widget},
    Frame,
};

use crate::traits::{IEventHandler, IPresenter, IVisible, IWindow};

use super::{
    action::{Action, UiActions},
    focus_tracker::FocusTracker,
    tools::centered_rect_fixed,
    widgets::button::ButtonElement,
    window::{LayoutMap, WidgetMap},
};

pub struct Dialog<D> {
    name: String,
    focus: FocusTracker,
    size: (u16, u16),
    buttons: Vec<String>,
    state: D,
    layout: LayoutMap,
    widgets: WidgetMap,
}

impl<D: 'static> Dialog<D> {
    pub fn new<S: Into<String>>(
        size: (u16, u16),
        name: S,
        buttons: Vec<S>,
        focused_button: &str,
        state: D,
    ) -> Self {
        let buttons: Vec<String> = buttons.into_iter().map(|s| s.into()).collect();
        // create buttons and add them to the window builder
        let mut widgets = WidgetMap::new();
        for button_name in buttons.iter() {
            let button = ButtonElement::new(button_name);
            widgets.insert(button_name.into(), Box::new(button));
        }

        let focus = FocusTracker::new(
            buttons.clone(),
            Some(focused_button.to_string()),
            super::focus_tracker::FocusMode::Wrap,
        );

        Self {
            name: name.into(),
            focus,
            widgets,
            size,
            buttons,
            state,
            layout: LayoutMap::new(),
        }
    }

    fn on_ok_yes<F>(_f: F) -> Option<UiActions>
    where
        F: Fn(&D) -> Option<UiActions>,
    {
        Some(UiActions::ButtonClicked("Ok".to_string()))
    }

    fn do_layout(&mut self, area: &Rect) {
        let dialog_area = centered_rect_fixed(self.size.0, self.size.1, *area);
        self.layout.insert("frame".to_string(), dialog_area);
        // split the dialog area into two parts: content and buttons
        let max_button_len = self.buttons.iter().map(|b| b.len() + 2).max().unwrap_or(0) as u16;
        let num_buttons = self.buttons.len();

        let layout = layout::Layout::horizontal([
            layout::Constraint::Min(0),
            layout::Constraint::Length(max_button_len),
        ])
        .margin(1)
        .split(dialog_area);

        let content_rect = layout[0];
        let buttons_rect = layout[1];

        // split the buttons area into buttons
        let button_layout = layout::Layout::vertical(vec![Constraint::Length(3); num_buttons])
            .flex(Flex::Start)
            .split(buttons_rect);

        for (i, button) in self.buttons.iter().enumerate() {
            self.layout.insert(button.clone(), button_layout[i]);
        }
        self.layout.insert("content".to_string(), content_rect);
    }

    fn render_contents(&self, area: &Rect, frame: &mut Frame<'_>, _focused: bool) {
        info!("Rendering dialog content");
        frame.render_widget(Paragraph::new("AAAAAARRRRRRGGGGHHHHH"), *area);
    }
}

impl<D: 'static> IWindow for Dialog<D> {}

impl<D: 'static> IPresenter for Dialog<D> {
    // fn do_layout(&mut self, area: &Rect) -> HashMap<String, Rect> {
    //     self.do_layout(area);
    //     // get content area and pass it to window
    //     let content_area = self.layout.get("content").unwrap();

    //     self.w.do_layout(&content_area);
    //     HashMap::new()
    // }

    fn render(
        &mut self,
        area: &Rect,
        frame: &mut Frame<'_>,
        _model: &Rc<Model>,
        dialog_focused: bool,
    ) {
        trace!("Rendering dialog: {}", self.name);
        self.do_layout(area);

        // render the dialog
        let frame_rect = self.layout.get("frame").unwrap();
        Clear.render(*frame_rect, frame.buffer_mut());

        let block = Block::default()
            .borders(Borders::ALL)
            //FIXME: need new Font
            //.border_type(BorderType::Thick)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::White))
            .style(Style::default().bg(Color::Black))
            .title(self.name.as_str());

        block.render(*frame_rect, frame.buffer_mut());

        let focused_button = self
            .focus
            .get_focused_view()
            .unwrap_or("".to_string());

        debug!("focused button: {focused_button}");

        // render the buttons
        for button_name in self.buttons.iter() {
            let button_rect = self.layout.get(button_name).unwrap();
            let button = self.widgets.get_mut(button_name).unwrap();
            button.render(
                button_rect,
                frame,
                (*button_name == focused_button) && dialog_focused,
            );
        }

        // render the content
        // if let Some(self.state){}
        let content_area = *self.layout.get("content").unwrap();
        self.render_contents(&content_area, frame, dialog_focused);
    }

    fn can_focus(&self) -> bool {
        true
    }
}

impl<D> IVisible for Dialog<D> {}
impl<D> IEventHandler for Dialog<D> {
    fn handle_event(&mut self, event: events::Event) -> Option<Action> {
        match event {
            events::Event::Key(key) => {
                let next_action = self.handle_key_event(key)?;
                Some(Action::new(&self.name, next_action))
            }
            _ => None,
        }
    }
}
impl<D> IElementEventHandler for Dialog<D> {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<UiActions> {
        trace!("Handling key event for dialog {}: {:?}", self.name, key);
        // if Escape is pressed then dismiss the dialog
        if key.code == crossterm::event::KeyCode::Esc {
            trace!("Dismissing dialog: {}", self.name);
            return Some(UiActions::DismissDialog);
        }

        if let Some(action) = self.focus.handle_key_event(key) {
            return Some(action);
        }

        if let Some(action) = self
            .widgets
            .get_mut(&self.focus.get_focused_view()?)
            .unwrap()
            .handle_key_event(key)
        {
            match action {
                UiActions::ButtonClicked(ref name) => {
                    if name == "Ok" || name == "Yes" {
                        return Some(action);
                    } else {
                        return Some(UiActions::DismissDialog);
                    }
                }
                _ => return Some(action),
            }
        }
        None
    }
}
