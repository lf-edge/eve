// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Intended trait API surface for the UI/presenter framework; some default
// methods and helper traits are not yet exercised by every caller.
#![allow(dead_code)]

use std::any::Any;
use std::rc::Rc;

use crate::events::Event;
use crate::model::model::Model;
use crate::ui::action::{Action, UiActions};
use crate::ui::activity::Activity;
use log::info;
use ratatui::{layout::Rect, Frame};

pub trait IPresenter {
    // fn do_layout(&mut self, area: &Rect) -> HashMap<String, Rect>;
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, model: &Rc<Model>, focused: bool);
    fn can_focus(&self) -> bool {
        true
    }
}

pub trait IVisible {
    fn is_visible(&self) -> bool {
        true
    }
    fn set_visible(&mut self, _visible: bool) {}
}

pub trait IEventHandler {
    fn handle_event(&mut self, _event: Event) -> Option<Action> {
        None
    }
}

pub trait IElementEventHandler {
    fn handle_key_event(&mut self, _key: crossterm::event::KeyEvent) -> Option<UiActions> {
        None
    }
    fn handle_tick(&mut self) -> Option<Activity> {
        None
    }
}

pub trait IWidgetPresenter {
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, focused: bool);
    fn can_focus(&self) -> bool {
        true
    }
}

pub trait IWindow: IPresenter + IEventHandler {
    fn on_child_action(&mut self, source: String, action: UiActions) -> Option<Action> {
        info!("Window received child action: {:?} from {}", action, source);
        None
    }
    fn status_bar_tips(&self) -> Option<String> {
        None
    }
}
pub trait IWidget: IWidgetPresenter + IElementEventHandler {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn set_enabled(&mut self, _enabled: bool) {}
    fn is_enabled(&self) -> bool {
        true
    }
    fn tips_in_focus(&self) -> Option<String> {
        None
    }
    fn as_input_field_mut(&self) -> Option<&mut dyn TextInput> {
        None
    }
}

pub trait IAction: Clone {
    type Target;
    fn get_source(&self) -> &str;
    fn get_target(&self) -> Option<&str>;
    fn split(self) -> (String, Self::Target);
}

pub trait TextInput {
    fn text(&self) -> &str;
    fn set_text(&mut self, s: String);
    fn set_error(&mut self, msg: Option<String>);
}
