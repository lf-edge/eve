// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use ratatui::style::Style;

pub trait IntoRatatuiStyle {
    fn style(&self) -> Style;
}

pub trait ISelectable {
    type Item;
    fn current_index(&self) -> Option<usize>;
    fn selection_size(&self) -> usize;
    fn select(&mut self, index: usize);
    fn selected_item(&self) -> Option<Self::Item>;
}

pub trait ISelector {
    type Item;
    fn select_next(&mut self);
    fn select_previous(&mut self);
    fn select_first(&mut self);
    fn select_last(&mut self);
    fn select_forward_by(&mut self, count: usize) {}
    fn select_backward_by(&mut self, count: usize) {}
    fn selected(&self) -> Option<Self::Item>;
}

impl<I, T> ISelector for T
where
    T: ISelectable<Item = I>,
{
    type Item = I;
    fn select_next(&mut self) {
        if let Some(index) = self.current_index() {
            let next_index = (index + 1) % self.selection_size();
            self.select(next_index);
        } else {
            self.select_first();
        }
    }

    fn select_previous(&mut self) {
        if let Some(index) = self.current_index() {
            let previous_index = if index == 0 {
                self.selection_size() - 1
            } else {
                index - 1
            };
            self.select(previous_index);
        }
    }

    fn select_first(&mut self) {
        self.select(0);
    }

    fn select_last(&mut self) {
        self.select(self.selection_size() - 1);
    }

    fn selected(&self) -> Option<Self::Item> {
        // call selected from ISelectable
        self.selected_item()
    }

    fn select_forward_by(&mut self, count: usize) {
        if let Some(index) = self.current_index() {
            let next_index = (index + count) % self.selection_size();
            self.select(next_index);
        } else {
            self.select_first();
        }
    }

    fn select_backward_by(&mut self, count: usize) {
        if let Some(index) = self.current_index() {
            let previous_index = if index == 0 {
                self.selection_size().saturating_sub(count)
            } else {
                index.saturating_sub(count)
            };
            self.select(previous_index);
        }
    }
}
