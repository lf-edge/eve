// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use ratatui::layout::{Constraint, Layout, Rect};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

// helper function to create a centered rect using up certain percentage of the available rect `r`
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

pub fn centered_rect_fixed(width: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Length(r.height.saturating_sub(height) / 2),
        Constraint::Length(height),
        Constraint::Length(r.height.saturating_sub(height) / 2),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Length(r.width.saturating_sub(width) / 2),
        Constraint::Length(width),
        Constraint::Length(r.width.saturating_sub(width) / 2),
    ])
    .split(popup_layout[1])[1]
}
// Generic UI helper container; intended utility API not yet used by a caller.
#[allow(dead_code)]
#[derive(Default)]
pub struct ElementHashMap<T> {
    layout: HashMap<String, T>,
}

#[allow(dead_code)]
impl<T> ElementHashMap<T> {
    pub fn new() -> Self {
        Self {
            layout: HashMap::new(),
        }
    }
    /// Returns error if the name already exists
    pub fn add_or_update(&mut self, name: String, elem: T) -> Option<T> {
        self.layout.insert(name, elem)
    }
    pub fn clear(&mut self) {
        self.layout.clear();
    }
}

impl<T> Deref for ElementHashMap<T> {
    type Target = HashMap<String, T>;
    fn deref(&self) -> &Self::Target {
        &self.layout
    }
}

impl<T> DerefMut for ElementHashMap<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.layout
    }
}

// EXAMPLE to be removed
// impl Debug for Window {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Window")
//             .field("id", &self.id)
//             .field("views", &self.views)
//             .field("focus_tracker", &self.focus_tracker)
//             .finish()
//     }
// }

// /// WindowId is a unique identifier for a window that is incremented sequentially.
// pub type WindowId = usize;

// struct WindowIdGenerator(AtomicUsize);
// impl WindowIdGenerator {
//     fn next(&self) -> WindowId {
//         self.0.fetch_add(1, Ordering::SeqCst)
//     }
// }

// // statically initialize the window id counter
// static WIN_ID: WindowIdGenerator = WindowIdGenerator(AtomicUsize::new(1));
// /// TARGET_APP_ID is a special identifier to roue events to the application's event loop.
// pub static TARGET_APP_ID: WindowId = 0;
