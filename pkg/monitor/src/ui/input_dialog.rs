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

use crate::{actions::MonActions, model::model::Model, traits::IWindow, ui::action::UiActions};

use super::{
    action::Action,
    widgets::{button::ButtonElement, input_field::InputFieldElement},
    window::Window,
};

struct InputDialogState {
    caption: String,
    content: String,
    hint: String,
}

fn on_init(w: &mut Window<InputDialogState>) {
    w.add_widget(
        "input",
        InputFieldElement::new(w.state.caption.clone(), Some(w.state.content.clone()))
            .with_text_hint(w.state.hint.clone()),
    );
    // buttons
    w.add_widget("ok", ButtonElement::new("ok"));
    w.add_widget("cancel", ButtonElement::new("cancel"));

    w.set_focus_tracker_tab_order(vec!["input", "ok", "cancel"]);
}

fn do_render(
    w: &mut Window<InputDialogState>,
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

fn do_layout(w: &mut Window<InputDialogState>, rect: &Rect, _model: &Rc<Model>) {
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
    w.update_layout("input", tabs);

    // buttons
    let [ok, cancel] = Layout::horizontal(vec![Constraint::Length(6), Constraint::Length(10)])
        .flex(Flex::End)
        .areas(buttons);
    w.update_layout("ok", ok);
    w.update_layout("cancel", cancel);
}

fn on_key_event(w: &mut Window<InputDialogState>, key: KeyEvent) -> Option<Action> {
    debug!("ip_dialog: on_key_event");

    if key.code == KeyCode::Esc {
        return Some(Action::new(&w.name, UiActions::DismissDialog));
    }
    None
}

fn on_child_ui_action(
    w: &mut Window<InputDialogState>,
    source: &String,
    action: &UiActions,
) -> Option<Action> {
    debug!("on_child_ui_action: {}:{:?}", source, action);
    match action {
        UiActions::ButtonClicked(name) => match name.as_str() {
            "cancel" => Some(Action::new(&w.name, UiActions::DismissDialog)),
            "ok" => Some(Action::new(
                &w.name,
                UiActions::AppAction(MonActions::ServerUpdated(w.state.content.clone())),
            )),
            _ => None,
        },
        UiActions::Input { text } => {
            if source.as_str() == "input" { w.state.content = text.clone() }
            None
        }
        _ => None,
    }
}

pub fn create_input_dialog(
    window_caption: &str,
    caption: &str,
    content: &str,
    hint: &str,
) -> impl IWindow {

    Window::builder(window_caption)
        .with_on_init(on_init)
        .with_layout(do_layout)
        .with_render(do_render)
        .with_on_key_event(on_key_event)
        .with_on_child_ui_action(on_child_ui_action)
        .with_state(InputDialogState {
            caption: caption.to_string(),
            content: content.to_string(),
            hint: hint.to_string(),
        })
        .build()
        .unwrap()
}
