// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use crossterm::event::{KeyCode, KeyEvent};
use log::debug;
use ratatui::{
    layout::{Constraint, Flex, Layout, Margin, Rect},
    style::{Color, Style},
    widgets::{Block, BorderType, Borders, Clear},
    Frame,
};

use crate::{model::model::Model, traits::IWindow, ui::action::UiActions};

use super::{
    action::Action,
    widgets::{button::ButtonElement, label::LabelElement},
    window::Window,
};

struct MessageBoxState {
    content: String,
}

fn on_init(w: &mut Window<MessageBoxState>) {
    w.add_widget("label", LabelElement::new(w.state.content.clone()));
    // buttons
    w.add_widget("ok", ButtonElement::new("ok"));
    w.add_widget("cancel", ButtonElement::new("cancel"));

    w.set_focus_tracker_tab_order(vec!["ok", "cancel"]);
}

fn do_render(
    w: &mut Window<MessageBoxState>,
    _rect: &Rect,
    frame: &mut Frame<'_>,
    _model: &Rc<Model>,
) {
    // render frame
    let frame_rect = w.get_layout("frame");

    // clear area under the dialog
    let clear = Clear {};
    frame.render_widget(clear, frame_rect);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::White))
        .style(Style::default().bg(Color::Black))
        .title(w.name.clone());

    frame.render_widget(block, frame_rect);
}

fn do_layout(w: &mut Window<MessageBoxState>, rect: &Rect, _model: &Rc<Model>) {
    debug!("do_layout. selected tab");

    let rect = crate::ui::tools::centered_rect_fixed(40, 10, *rect);
    let content_with_buttons = rect.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });

    w.update_layout("frame", rect);

    // split content are
    let [dialog_content, buttons] =
        Layout::vertical(vec![Constraint::Fill(1), Constraint::Length(3)])
            .flex(Flex::End)
            .areas(content_with_buttons);

    // split dialog content area. Top - Input widget
    let [tabs, _dialog_content_rect] =
        Layout::vertical(vec![Constraint::Length(3), Constraint::Fill(1)]).areas(dialog_content);
    w.update_layout("label", tabs);

    // buttons
    let [ok, cancel] = Layout::horizontal(vec![Constraint::Length(6), Constraint::Length(10)])
        .flex(Flex::End)
        .areas(buttons);
    w.update_layout("ok", ok);
    w.update_layout("cancel", cancel);
}

fn on_key_event(w: &mut Window<MessageBoxState>, key: KeyEvent) -> Option<Action> {
    debug!("message_box: on_key_event");

    if key.code == KeyCode::Esc {
        return Some(Action::new(&w.name, UiActions::DismissDialog));
    }
    None
}

fn on_child_ui_action(
    w: &mut Window<MessageBoxState>,
    source: &String,
    action: &UiActions,
) -> Option<Action> {
    debug!("on_child_ui_action: {}:{:?}", source, action);
    match action {
        UiActions::ButtonClicked(name) => match name.as_str() {
            _ => Some(Action::new(&w.name, UiActions::DismissDialog)),
        },
        _ => None,
    }
}

pub fn create_message_box(window_caption: &str, content: &str) -> impl IWindow {
    let w = Window::builder(window_caption)
        .with_on_init(on_init)
        .with_layout(do_layout)
        .with_render(do_render)
        .with_on_key_event(on_key_event)
        .with_on_child_ui_action(on_child_ui_action)
        .with_state(MessageBoxState {
            content: content.to_string(),
        })
        .build()
        .unwrap();
    w
}

/// Creates a system (non-dismissable) message box.
/// It has no buttons and does not respond to Esc or any key events.
/// It can only be removed programmatically via `pop_layer()`.
pub fn create_system_message_box(window_caption: &str, content: &str) -> impl IWindow {
    fn sys_on_init(w: &mut Window<MessageBoxState>) {
        w.add_widget("label", LabelElement::new(w.state.content.clone()));
    }

    fn sys_do_layout(w: &mut Window<MessageBoxState>, rect: &Rect, _model: &Rc<Model>) {
        let rect = crate::ui::tools::centered_rect_fixed(40, 7, *rect);
        let content_area = rect.inner(Margin {
            horizontal: 1,
            vertical: 1,
        });

        w.update_layout("frame", rect);
        w.update_layout("label", content_area);
    }

    // Swallow all key events — the popup cannot be dismissed by the user
    fn sys_on_key_event(_w: &mut Window<MessageBoxState>, _key: KeyEvent) -> Option<Action> {
        None
    }

    let w = Window::builder(window_caption)
        .with_on_init(sys_on_init)
        .with_layout(sys_do_layout)
        .with_render(do_render)
        .with_on_key_event(sys_on_key_event)
        .with_state(MessageBoxState {
            content: content.to_string(),
        })
        .build()
        .unwrap();
    w
}
