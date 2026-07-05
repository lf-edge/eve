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

use crate::{model::model::Model, traits::IWindow, ui::action::UiActions, actions::MonActions};

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
    w.add_widget("ok", ButtonElement::new("ok"));

    w.set_focus_tracker_tab_order(vec!["ok"]);
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

    // Leave a blank line between the dialog's frame title and the message
    // text below it, so the two don't visually run into each other.
    let [_spacer, tabs] =
        Layout::vertical(vec![Constraint::Length(1), Constraint::Fill(1)]).areas(dialog_content);
    w.update_layout("label", tabs);

    // button
    let [ok] = Layout::horizontal(vec![Constraint::Length(6)])
        .flex(Flex::End)
        .areas(buttons);
    w.update_layout("ok", ok);
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
        UiActions::ButtonClicked(_name) => Some(Action::new(&w.name, UiActions::DismissDialog)),
        _ => None,
    }
}

pub fn create_message_box(window_caption: &str, content: &str) -> impl IWindow {

    Window::builder(window_caption)
        .with_on_init(on_init)
        .with_layout(do_layout)
        .with_render(do_render)
        .with_on_key_event(on_key_event)
        .with_on_child_ui_action(on_child_ui_action)
        .with_state(MessageBoxState {
            content: content.to_string(),
        })
        .build()
        .unwrap()
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


    Window::builder(window_caption)
        .with_on_init(sys_on_init)
        .with_layout(sys_do_layout)
        .with_render(do_render)
        .with_on_key_event(sys_on_key_event)
        .with_state(MessageBoxState {
            content: content.to_string(),
        })
        .build()
        .unwrap()
}

struct ConfirmDialogState {
    content: String,
    // Fired (wrapped in UiActions::AppAction) when the user confirms ("yes").
    confirm_action: MonActions,
}

fn confirm_on_init(w: &mut Window<ConfirmDialogState>) {
    w.add_widget("label", LabelElement::new(w.state.content.clone()));
    w.add_widget("yes", ButtonElement::new("yes"));
    w.add_widget("no", ButtonElement::new("no"));
    // Default focus on "no" so an accidental Enter does not confirm a
    // destructive action.
    w.set_focus_tracker_tab_order(vec!["no", "yes"]);
}

fn confirm_do_render(
    w: &mut Window<ConfirmDialogState>,
    _rect: &Rect,
    frame: &mut Frame<'_>,
    _model: &Rc<Model>,
) {
    let frame_rect = w.get_layout("frame");

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

fn confirm_do_layout(w: &mut Window<ConfirmDialogState>, rect: &Rect, _model: &Rc<Model>) {
    let rect = crate::ui::tools::centered_rect_fixed(50, 10, *rect);
    let content_with_buttons = rect.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });

    w.update_layout("frame", rect);

    let [dialog_content, buttons] =
        Layout::vertical(vec![Constraint::Fill(1), Constraint::Length(3)])
            .flex(Flex::End)
            .areas(content_with_buttons);

    // Leave a blank line between the dialog's frame title and the question
    // text below it, so the two don't visually run into each other.
    let [_spacer, label_rect] =
        Layout::vertical(vec![Constraint::Length(1), Constraint::Fill(1)]).areas(dialog_content);
    w.update_layout("label", label_rect);

    let [no, yes] = Layout::horizontal(vec![Constraint::Length(8), Constraint::Length(8)])
        .flex(Flex::End)
        .areas(buttons);
    w.update_layout("no", no);
    w.update_layout("yes", yes);
}

fn confirm_on_key_event(w: &mut Window<ConfirmDialogState>, key: KeyEvent) -> Option<Action> {
    if key.code == KeyCode::Esc {
        return Some(Action::new(&w.name, UiActions::DismissDialog));
    }
    None
}

fn confirm_on_child_ui_action(
    w: &mut Window<ConfirmDialogState>,
    _source: &String,
    action: &UiActions,
) -> Option<Action> {
    debug!("confirm_on_child_ui_action: {:?}", action);
    match action {
        UiActions::ButtonClicked(name) if name == "yes" => Some(Action::new(
            &w.name,
            UiActions::AppAction(w.state.confirm_action.clone()),
        )),
        UiActions::ButtonClicked(_) => Some(Action::new(&w.name, UiActions::DismissDialog)),
        _ => None,
    }
}

/// Creates a Yes/No confirmation dialog. Confirming ("yes") fires
/// `confirm_action` (wrapped in `UiActions::AppAction`); "no" or Esc just
/// dismisses the dialog with no further action.
pub fn create_confirm_dialog(
    window_caption: &str,
    content: &str,
    confirm_action: MonActions,
) -> impl IWindow {
    Window::builder(window_caption)
        .with_on_init(confirm_on_init)
        .with_layout(confirm_do_layout)
        .with_render(confirm_do_render)
        .with_on_key_event(confirm_on_key_event)
        .with_on_child_ui_action(confirm_on_child_ui_action)
        .with_state(ConfirmDialogState {
            content: content.to_string(),
            confirm_action,
        })
        .build()
        .unwrap()
}
