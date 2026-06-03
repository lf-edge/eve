// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::{
    layout::{Alignment, Constraint, Rect},
    style::{Color, Style},
    text::Text,
    widgets::{
        Block, BorderType, Borders, Cell, HighlightSpacing, Padding, Row, StatefulWidget, Table,
        TableState,
    },
    Frame,
};

use crate::{
    events::Event,
    model::model::{AppInstance, AppInstanceState, Model},
    traits::{IEventHandler, IPresenter, IWindow},
};

use super::traits::{ISelectable, ISelector};

#[derive(Debug, Default)]
struct ApplicationList {
    state: TableState,
    size: usize,
}

impl ISelectable for ApplicationList {
    type Item = String;

    fn current_index(&self) -> Option<usize> {
        self.state.selected()
    }

    fn selection_size(&self) -> usize {
        self.size
    }

    fn select(&mut self, index: usize) {
        self.state.select(Some(index));
    }

    fn selected_item(&self) -> Option<Self::Item> {
        None
    }
}

#[derive(Debug, Default)]
pub struct ApplicationsPage {
    list: ApplicationList,
}

impl ApplicationsPage {
    pub fn new() -> Self {
        ApplicationsPage {
            ..Default::default()
        }
    }
    fn render_app_list(&mut self, model: &Rc<Model>, list_rect: Rect, frame: &mut Frame) {
        // create header for the table
        let header = Row::new(vec![
            Cell::from("Name").style(Style::default()),
            Cell::from("GUID").style(Style::default()),
            Cell::from("Status").style(Style::default()),
        ]);

        // create list items from the interface
        let rows = model
            .borrow()
            .apps.values().map(info_row_from_app)
            .collect::<Vec<_>>();

        self.list.size = rows.len();

        // create a surrounding block for the list
        let block = Block::default()
            .title(" Applications ")
            .title_alignment(Alignment::Center)
            .borders(Borders::TOP)
            .border_type(BorderType::Plain)
            // .border_style(Style::default().fg(Color::White).bg(Color::Black))
            // .style(Style::default().bg(Color::Black));
            .padding(Padding::new(1, 1, 1, 1));

        let bar = " █ ";

        // Create a List from all list items and highlight the currently selected one
        let list = Table::new(
            rows,
            [
                Constraint::Max(20),
                Constraint::Max(32),
                Constraint::Fill(14),
            ],
        )
        .block(block)
        .row_highlight_style(Style::new().bg(Color::DarkGray))
        // .highlight_symbol(">")
        .highlight_symbol(Text::from(vec![
            // "".into(),
            bar.into(),
            bar.into(),
            bar.into(),
            bar.into(),
            // "".into(),
        ]))
        .highlight_spacing(HighlightSpacing::Always)
        .header(header);

        StatefulWidget::render(list, list_rect, frame.buffer_mut(), &mut self.list.state);
    }
}

impl IWindow for ApplicationsPage {}

impl IEventHandler for ApplicationsPage {
    fn handle_event(&mut self, event: Event) -> Option<super::action::Action> {
        if let Event::Key(key) = event { match key.code {
            KeyCode::Up => self.list.select_previous(),
            KeyCode::Down => self.list.select_next(),
            KeyCode::Home if key.modifiers == KeyModifiers::CONTROL => self.list.select_first(),
            KeyCode::End if key.modifiers == KeyModifiers::CONTROL => self.list.select_last(),
            _ => {}
        } }
        None
    }
}

fn info_row_from_app<'b>(app: &AppInstance) -> Row<'b> {
    let height = 1;
    // cells #1,2 IFace name and Link status
    let cells = vec![
        Cell::from(app.name.clone()),
        Cell::from(app.uuid.to_string()),
        match &app.state {
            AppInstanceState::Normal(st) => {
                Cell::from(format!("{:?}", st)).style(Style::new().green())
            }
            AppInstanceState::Error(st, _err) => {
                Cell::from(format!("{:?}", st)).style(Style::new().red())
            }
        },
    ];

    Row::new(cells).height(height)
}

impl IPresenter for ApplicationsPage {
    fn render(
        &mut self,
        area: &ratatui::prelude::Rect,
        frame: &mut ratatui::Frame<'_>,
        model: &std::rc::Rc<Model>,
        _focused: bool,
    ) {
        self.render_app_list(model, *area, frame);
    }
}
