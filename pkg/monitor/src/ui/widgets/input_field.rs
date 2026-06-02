// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crossterm::event::{KeyCode, KeyEvent};
use log::trace;
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Rect, Size},
    style::{Color, Style},
    widgets::{Block, BorderType, Borders, Paragraph, Widget},
};

use crate::{
    traits::{IElementEventHandler, IWidget, IWidgetPresenter, TextInput},
    ui::action::UiActions,
};

#[derive(Debug, Clone, PartialEq)]
enum InputMode {
    Insert,
    Overwrite,
}

impl InputMode {
    pub fn toggle(&mut self) {
        match self {
            Self::Insert => *self = Self::Overwrite,
            Self::Overwrite => *self = Self::Insert,
        }
    }
}

pub type OnContentUpdated = dyn FnMut(&String) -> Option<String>;
pub type OnChar = dyn FnMut(&char) -> Option<char>;
pub type ValidateFn = dyn Fn(&String) -> Result<(), String>;

#[derive(PartialEq)]
pub enum InputModifiers {
    DisplayMode,
    DisplayPosition,
    DisplayCaption,
}

pub struct InputFieldElement {
    caption: String,
    value: Option<String>,
    input_position: usize,
    cursor_position: u16,
    scroll_left: u16,
    text_area: Rect,
    input_mode: InputMode,
    on_char: Option<Box<OnChar>>,
    on_validate: Option<Box<ValidateFn>>,
    validation_error: Option<String>,
    enabled: bool,
    modifiers: Vec<InputModifiers>,
    size_hint: Option<Size>,
    text_hint: Option<String>,
}

impl TextInput for InputFieldElement {
    fn text(&self) -> &str {
        self.value.as_deref().unwrap_or_default()
    }
    fn set_text(&mut self, s: String) {
        self.value = Some(s);
    }
    fn set_error(&mut self, msg: Option<String>) {
        self.validation_error = msg;
    }
}

impl IWidget for InputFieldElement {
    fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn tips_in_focus(&self) -> Option<String> {
        return self.validation_error.clone();
    }
}

impl InputFieldElement {
    pub fn new<S: Into<String>>(caption: S, value: Option<S>) -> Self {
        let value = value.map(|v| v.into());
        let input_position = value.as_ref().map(|v| v.len()).unwrap_or_default();

        let caption = caption.into();
        Self {
            caption,
            value,
            input_position,
            cursor_position: input_position as u16,
            input_mode: InputMode::Insert,
            on_char: Some(Box::new(|c| Some(*c))),
            on_validate: None,
            validation_error: None,
            text_area: Rect::default(),
            scroll_left: 0,
            enabled: true,
            modifiers: vec![
                // InputModifiers::DisplayMode,
                // InputModifiers::DisplayPosition,
                InputModifiers::DisplayCaption,
            ],
            size_hint: None,
            text_hint: None,
        }
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_modifiers(mut self, modifiers: Vec<InputModifiers>) -> Self {
        self.modifiers = modifiers;
        self
    }

    pub fn with_size_hint(mut self, size_hint: Size) -> Self {
        self.size_hint = Some(size_hint);
        self
    }

    pub fn with_text_hint<S: Into<String>>(mut self, text_hint: S) -> Self {
        self.text_hint = Some(text_hint.into());
        self
    }

    pub fn validate<F>(mut self, f: F) -> Self
    where
        F: Fn(&String) -> Result<(), String> + 'static,
    {
        self.on_validate = Some(Box::new(f));
        self
    }

    pub fn on_char<F>(mut self, f: F) -> Self
    where
        F: FnMut(&char) -> Option<char> + 'static,
    {
        self.on_char = Some(Box::new(f));
        self
    }

    fn render_input_field(&mut self, area: &Rect, buf: &mut Buffer, focused: bool) {
        let style = match (self.is_enabled(), focused) {
            (false, _) => Style::default().fg(Color::DarkGray),
            (true, false) => Style::default().fg(Color::White),
            (true, true) => Style::default().fg(Color::Yellow),
        };

        // render INS/OVR indicator next to the caption
        let mode = match self.input_mode {
            InputMode::Insert => "INS",
            InputMode::Overwrite => "OVR",
        };

        let mut blk = Block::new()
            //.border_type(BorderType::Rounded)
            //FIXME: need new Font
            .border_type(BorderType::Plain)
            .borders(Borders::ALL)
            .style(Style::default().bg(Color::Black));

        // set foreground color to red if validation error is present
        if self.validation_error.is_some() {
            blk = blk.border_style(Style::default().fg(Color::Red));
        } else {
            blk = blk.border_style(style);
        }

        // render caption
        if self.modifiers.contains(&InputModifiers::DisplayCaption) {
            let caption = if self.modifiers.contains(&InputModifiers::DisplayMode) {
                format!("{}: {}", self.caption, mode)
            } else {
                self.caption.clone()
            };
            blk = blk.title(caption);
        }

        // render pos/total in the bottom right corner
        if self.modifiers.contains(&InputModifiers::DisplayPosition) {
            let pos = format!(
                "{}/{}",
                self.input_position,
                self.value.as_ref().map(|v| v.len()).unwrap_or_default()
            );
            blk = blk.title_bottom(pos);
        }

        // take size hist into account
        let area = self.size_hint.map_or_else(
            || *area,
            |s| {
                area.clamp(Rect {
                    x: area.x,
                    y: area.y,
                    width: s.width,
                    height: s.height,
                })
            },
        );

        // get inner area
        let inner_area = blk.inner(area);
        self.text_area = inner_area;
        // render the border and caption
        blk.render(area, buf);

        // if value is empty, render the text hint
        if self.value.as_ref().map(|v| v.is_empty()).unwrap_or(true) {
            if let Some(text_hint) = self.text_hint.as_deref() {
                let hint = Paragraph::new(text_hint)
                    .style(Style::default().fg(Color::DarkGray))
                    .alignment(Alignment::Left);
                hint.render(inner_area, buf);
            }
            return;
        }

        // render the input field
        let input = Paragraph::new(self.value.as_deref().unwrap_or_default())
            .style(Style::default().fg(Color::White))
            .alignment(Alignment::Left)
            .scroll((0, self.scroll_left)); // note reversed order (y,x)

        input.render(inner_area, buf);
    }

    pub fn text(&self) -> Option<String> {
        self.value.clone()
    }
}

impl IElementEventHandler for InputFieldElement {
    fn handle_key_event(&mut self, key: KeyEvent) -> Option<UiActions> {
        trace!("input element {} handling key {:?}", self.caption, key.code);
        let old_value = self.value.clone();
        let is_enabled = self.is_enabled();
        if let Some(value) = self.value.as_mut() {
            match key.code {
                KeyCode::Char(c) => {
                    if !is_enabled {
                        return None;
                    }

                    if let Some(f) = self.on_char.as_mut() {
                        if let Some(c) = f(&c) {
                            if self.input_mode == InputMode::Overwrite {
                                if self.input_position < value.len() {
                                    value.remove(self.input_position);
                                }
                            }
                            value.insert(self.input_position, c);
                            self.input_position += 1;
                            if self.cursor_position < self.text_area.width - 1 {
                                self.cursor_position += 1;
                            } else {
                                self.scroll_left += 1;
                            }
                        }
                    }
                }
                KeyCode::Backspace => {
                    if !is_enabled {
                        return None;
                    }
                    if self.input_position > 0 {
                        value.remove(self.input_position - 1);
                        self.input_position -= 1;
                        self.cursor_position = self.cursor_position.saturating_sub(1);
                    }
                }
                KeyCode::Delete => {
                    if !is_enabled {
                        return None;
                    }
                    if self.input_position < value.len() {
                        value.remove(self.input_position);
                    }
                }
                KeyCode::Left => {
                    self.input_position = self.input_position.saturating_sub(1);
                    if self.cursor_position == 0 {
                        self.scroll_left = self.scroll_left.saturating_sub(1);
                    }
                    self.cursor_position = self.cursor_position.saturating_sub(1);
                }
                KeyCode::Right => {
                    if self.input_position < value.len() {
                        self.input_position += 1;
                        if self.cursor_position < self.text_area.width {
                            self.cursor_position += 1;
                        }
                    }
                }
                KeyCode::Enter => {
                    // do nothing for now
                    // TODO: submit the value ?
                }
                KeyCode::End => {
                    self.input_position = value.len();
                    // self.cursor_position = self.input_position as u16 % self.text_area.width;
                    // self.scroll_left = self.input_position as u16 - self.cursor_position;
                    // OR
                    self.cursor_position =
                        (self.text_area.width - 1).min(self.input_position as u16);
                    self.scroll_left =
                        (self.input_position as u16).saturating_sub(self.cursor_position);
                }
                KeyCode::Home => {
                    self.input_position = 0;
                    self.cursor_position = 0;
                    self.scroll_left = 0;
                }
                KeyCode::Tab => {}
                KeyCode::BackTab => {}
                KeyCode::Insert => {
                    self.input_mode.toggle();
                }
                KeyCode::Esc => {}
                _ => {}
            }

            if let Some(validate_fn) = self.on_validate.as_mut() {
                self.validation_error = validate_fn(value).err();
            }

            if old_value != self.value {
                return Some(UiActions::Input {
                    text: self.value.clone().unwrap_or_default(),
                });
            }
        }
        None
    }
}

impl IWidgetPresenter for InputFieldElement {
    fn render(&mut self, area: &Rect, frame: &mut ratatui::Frame<'_>, focused: bool) {
        trace!(
            "rendering: InputFieldElement {:#?}. focused={}",
            &self.caption,
            focused
        );
        self.render_input_field(area, frame.buffer_mut(), focused);

        // set cursor position must be called every time to display the cursor
        // on the next redraw cycle
        if focused && self.is_enabled() {
            frame.set_cursor_position((self.text_area.x + self.cursor_position, self.text_area.y));
        }
    }
}
