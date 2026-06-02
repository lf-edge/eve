// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ui::action::UiActions;
use crossterm::event::KeyEvent;

use super::action::Action;

#[derive(Debug)]
pub enum Activity {
    Action(UiActions),
    Event(KeyEvent),
}

impl Activity {
    pub fn ui_action(action: UiActions) -> Self {
        Activity::Action(action)
    }

    pub fn key_event(key: KeyEvent) -> Self {
        Activity::Event(key)
    }

    pub fn redraw() -> Self {
        Activity::Action(UiActions::Redraw)
    }

    pub fn try_into_uiaction(self) -> Option<UiActions> {
        match self {
            Activity::Action(action) => Some(action),
            Activity::Event(_) => None,
        }
    }

    pub fn try_into_action<T>(self, source: T) -> Option<Action>
    where
        T: Into<String>,
    {
        match self {
            Activity::Action(uiaction) => Some(Action::new(source.into(), uiaction)),
            Activity::Event(_) => None,
        }
    }
}
