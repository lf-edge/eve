// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{actions::MonActions, traits::IAction};
#[derive(Debug, Clone, PartialEq)]
pub enum UiActions {
    Quit,
    Redraw,
    RadioGroup { selected: usize },
    SpinBox { selected: usize },
    Input { text: String },
    ButtonClicked(String),
    DismissDialog,
    AppAction(MonActions),
    EditIfaceConfig(String),
    TabChanged(String, String),
    ChangeServer,
}

#[derive(Debug, Clone)]
pub struct Action {
    pub source: String,
    pub target: Option<String>,
    pub action: UiActions,
}

impl Action {
    pub fn new<S: Into<String>>(source: S, action: UiActions) -> Self {
        Self {
            source: source.into(),
            action,
            target: None,
        }
    }
    pub fn target<S: Into<String>>(mut self, target: S) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn source<S: Into<String>>(mut self, source: S) -> Self {
        self.source = source.into();
        self
    }
}

impl IAction for Action {
    type Target = UiActions;
    fn get_source(&self) -> &str {
        &self.source
    }

    fn get_target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    fn split(self) -> (String, Self::Target) {
        (self.source, self.action)
    }
}
