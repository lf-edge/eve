// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use log::debug;
use ratatui::{
    style::Modifier,
    widgets::{Block, Tabs},
};

use crate::{
    traits::{IElementEventHandler, IWidget, IWidgetPresenter},
    ui::{
        action::UiActions,
        focus_tracker::{FocusMode, FocusTracker},
    },
};

pub struct TabElement {
    tabs: Vec<String>,
    ft: FocusTracker,
    caption: Option<String>,
}

impl TabElement {
    pub fn new<S: Into<String>>(tabs: Vec<S>, selected: &str, caption: Option<S>) -> Self {
        let tabs: Vec<String> = tabs.into_iter().map(|s| s.into()).collect();
        Self {
            tabs: tabs.clone(),
            ft: FocusTracker::new(tabs, Some(selected.to_string()), FocusMode::Wrap),
            caption: caption.map(|s| s.into()),
        }
    }
}

impl IWidget for TabElement {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
impl IWidgetPresenter for TabElement {
    fn render(
        &mut self,
        area: &ratatui::prelude::Rect,
        frame: &mut ratatui::Frame<'_>,
        _focused: bool,
    ) {
        debug!(
            "Rendering TabElement: selected_index={}",
            self.ft.get_focused_index()
        );
        let mut widget = Tabs::new(self.tabs.clone())
            .highlight_style(Modifier::REVERSED)
            .divider(" ")
            .padding("", "")
            .select(self.ft.get_focused_index());

        if let Some(caption) = &self.caption {
            let block = Block::new().title(caption.clone());
            widget = widget.block(block);
        }

        frame.render_widget(widget, *area);
    }
}

impl IElementEventHandler for TabElement {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<UiActions> {
        debug!("TabElement: Handling key event: {:?}", key);

        match &key.code {
            KeyCode::Left if key.modifiers == KeyModifiers::CONTROL => {
                let current = self.ft.get_focused_view().unwrap();
                self.ft.focus_prev();
                let new = self.ft.get_focused_view().unwrap();
                Some(UiActions::TabChanged(current, new))
            }
            KeyCode::Right if key.modifiers == KeyModifiers::CONTROL => {
                let current = self.ft.get_focused_view().unwrap();

                self.ft.focus_next();
                let new = self.ft.get_focused_view().unwrap();
                Some(UiActions::TabChanged(current, new))
            }
            _ => None,
        }
    }
}
