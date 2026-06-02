// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::IWindow;

pub struct LayerStack {
    layers: Vec<Box<dyn IWindow>>,
}

impl LayerStack {
    pub fn new() -> Self {
        Self { layers: Vec::new() }
    }
    pub fn push(&mut self, layer: Box<dyn IWindow>) {
        // clear focus on current top layer
        self.layers.push(layer);
    }
    pub fn pop(&mut self) -> Option<Box<dyn IWindow>> {
        self.layers.pop()
    }
    pub fn last_mut(&mut self) -> Option<&mut Box<dyn IWindow>> {
        self.layers.last_mut()
    }
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, Box<dyn IWindow>> {
        self.layers.iter_mut()
    }

    pub fn len(&self) -> usize {
        self.layers.len()
    }
}

impl Clone for LayerStack {
    fn clone(&self) -> Self {
        Self::new()
    }
}
