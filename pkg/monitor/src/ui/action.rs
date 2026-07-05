// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Core UI action/event API; some variants, fields and builder methods are part
// of the intended surface even when not yet exercised by every caller.
#![allow(dead_code)]

use crate::{actions::MonActions, traits::IAction};
// Variants carry app action state by value by design; do not box them.
#[allow(clippy::large_enum_variant)]
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
    RevertManualConfig,
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
