// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ui::action::UiActions;
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use log::debug;

use super::window::WidgetMap;

// use crate::traits::ViewComposer;
#[derive(Debug)]
pub enum FocusMode {
    Wrap,
    OneShot,
}
#[derive(Debug)]
pub struct FocusTracker {
    focused_view: usize,
    tab_order: Vec<String>,
    focus_mode: FocusMode,
    too_late: bool,
}

impl FocusTracker {
    pub fn new(
        tab_order: Vec<String>,
        focused_view: Option<String>,
        focus_mode: FocusMode,
    ) -> Self {
        // if focused view is set find its index in the tab order
        let focused_view = focused_view
            .and_then(|name| tab_order.iter().position(|n| n == &name))
            .unwrap_or(0);

        Self {
            focused_view,
            tab_order,
            focus_mode,
            too_late: false,
        }
    }

    pub fn create_from_taborder(
        tab_order: Vec<String>,
        focused_view: Option<String>,
        focus_mode: FocusMode,
    ) -> FocusTracker {
        let focus_tracker = FocusTracker::new(tab_order, focused_view, focus_mode);
        focus_tracker
    }

    pub fn create_from_views(
        views: &WidgetMap,
        focused_view: Option<String>,
        focus_mode: FocusMode,
    ) -> FocusTracker {
        let collect_views = || {
            let mut tab_order = Vec::new();

            for (view_name, view) in views.iter() {
                if view.can_focus() {
                    tab_order.push(view_name.clone());
                }
            }
            tab_order
        };

        let tab_order = collect_views();
        let focus_tracker = FocusTracker::new(tab_order, focused_view, focus_mode);
        focus_tracker
    }

    pub fn get_focused_view(&self) -> Option<String> {
        self.tab_order.get(self.focused_view).cloned()
    }

    pub fn get_focused_index(&self) -> usize {
        self.focused_view
    }

    pub fn set_focused_index(&mut self, index: usize) {
        self.focused_view = index;
    }

    pub fn focus_next(&mut self) -> Option<String> {
        if self.too_late {
            return None;
        }
        if self.focused_view + 1 < self.tab_order.len() {
            self.focused_view += 1;
        } else {
            if let FocusMode::Wrap = self.focus_mode {
                self.focused_view = 0;
            } else if let FocusMode::OneShot = self.focus_mode {
                self.too_late = true;
                return None;
            }
        }

        Some(self.tab_order[self.focused_view].clone())
    }

    pub fn focus_prev(&mut self) -> Option<String> {
        if self.too_late {
            return None;
        }
        if self.focused_view > 0 {
            self.focused_view -= 1;
        } else {
            if let FocusMode::Wrap = self.focus_mode {
                self.focused_view = self.tab_order.len() - 1;
            } else if let FocusMode::OneShot = self.focus_mode {
                self.too_late = true;
                return None;
            }
        }

        Some(self.tab_order[self.focused_view].clone())
    }

    pub fn clear_focus(&mut self) {
        self.focused_view = 0;
    }

    pub fn handle_key_event(&mut self, key: KeyEvent) -> Option<UiActions> {
        debug!("focus_tracker handle_event {:?}", key);

        match key.code {
            // handle Tab key
            KeyCode::Tab | KeyCode::BackTab => {
                if key.code == KeyCode::Tab {
                    self.focus_next();
                } else {
                    self.focus_prev();
                }
                return Some(UiActions::Redraw);
            }
            _ => return None,
        }
    }

    pub fn set_tab_order(&mut self, order: Vec<String>) {
        self.tab_order = order;
        debug!("new tab order {:?}", self.tab_order);
        if self.focused_view > self.tab_order.len() {
            self.focused_view = 0;
        }
    }
}
