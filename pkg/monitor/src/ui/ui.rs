// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    model::device::network::NetworkInterfaceStatus,
    traits::{IPresenter, IWindow},
    ui::{input_dialog::create_input_dialog, ipdialog::create_ip_dialog},
};
use core::fmt::Debug;
use crossterm::event::{KeyCode, KeyModifiers};
use log::{debug, info};
use ratatui::{
    layout::{
        Constraint::{Fill, Length},
        Layout,
    },
    style::{Color, Modifier, Stylize},
    text::Line,
    widgets::{Block, Clear, Paragraph, Tabs, Widget},
};
use std::rc::Rc;
use strum::{Display, EnumCount, EnumIter, FromRepr, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    events::Event,
    model::{device::dmesg::DmesgViewer, model::Model},
    terminal::TerminalWrapper,
    traits::IEventHandler,
    ui::action::UiActions,
};

use super::{
    action::Action,
    app_page::ApplicationsPage,
    layer_stack::LayerStack,
    message_box::create_system_message_box,
    networkpage::create_network_page,
    statusbar::{create_status_bar, StatusBarState},
    summary_page::SummaryPage,
    vaultpage::VaultPage,
    window::Window,
};

#[cfg(debug_assertions)]
use super::homepage::HomePage;

use std::result::Result::Ok;

use anyhow::Result;

pub struct Ui {
    pub terminal: TerminalWrapper,
    pub action_tx: UnboundedSender<Action>,
    pub views: Vec<LayerStack>,
    pub selected_tab: UiTabs,
    pub status_bar: Window<StatusBarState>,
    first_frame: bool,
    connection_popup_shown: bool,
}

#[derive(Default, Copy, Clone, Display, EnumIter, Debug, FromRepr, EnumCount)]
pub enum UiTabs {
    #[default]
    Summary,
    #[cfg(debug_assertions)]
    Home,
    Network,
    Applications,
    Vault,
    Dmesg,
}

impl Debug for Ui {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ui :)")
    }
}

impl Ui {
    pub fn new(action_tx: UnboundedSender<Action>, terminal: TerminalWrapper) -> Result<Self> {
        Ok(Self {
            terminal,
            action_tx,
            views: vec![LayerStack::new(); UiTabs::COUNT],
            selected_tab: UiTabs::default(),
            status_bar: create_status_bar(),
            first_frame: true,
            connection_popup_shown: false,
        })
    }

    fn tabs() -> Tabs<'static> {
        let tab_titles = UiTabs::iter().map(UiTabs::to_tab_title);
        let block = Block::new().title(" Use ctrl + ◄ ► to change tab");
        Tabs::new(tab_titles)
            .block(block)
            .highlight_style(Modifier::REVERSED)
            .divider(" ")
            .padding("", "")
    }

    pub fn init(&mut self) {
        self.views[UiTabs::Summary as usize].push(Box::new(SummaryPage::new()));
        #[cfg(debug_assertions)]
        {
            self.views[UiTabs::Home as usize].push(Box::new(HomePage::new()));
        }

        self.views[UiTabs::Network as usize].push(Box::new(create_network_page()));

        self.views[UiTabs::Applications as usize].push(Box::new(ApplicationsPage::new()));
        self.views[UiTabs::Dmesg as usize].push(Box::new(DmesgViewer::new()));
        self.views[UiTabs::Vault as usize].push(Box::new(VaultPage::new()));
    }

    pub fn draw(&mut self, model: Rc<Model>) {
        let screen_layout = Layout::vertical([Length(3), Fill(0), Length(3)]);
        let tabs_widget = Ui::tabs();
        let git_version = model.borrow().app_version.clone();

        //TODO: handle terminal event
        let _ = self.terminal.draw(|frame| {
            let area = frame.area();
            let [top_bar_rect, body_rect, statusbar_rect] = screen_layout.areas(area);

            if self.first_frame {
                self.first_frame = false;
                frame.render_widget(Clear, area);
            }

            let [tabs_rect, version_rect] =
                Layout::horizontal([Fill(0), Length(git_version.len() as u16)]).areas(top_bar_rect);

            let version_widget = Paragraph::new(git_version.clone()).fg(Color::DarkGray);
            frame.render_widget(version_widget, version_rect);

            tabs_widget
                .select(self.selected_tab as usize)
                .render(tabs_rect, frame.buffer_mut());

            // redraw from the bottom up
            let stack = &mut self.views[self.selected_tab as usize];
            let last_index = stack.len().saturating_sub(1);
            // get hint for the last layer
            {
                let mut model = model.borrow_mut();

                let hint = if let Some(top) = stack.last_mut() {
                    top.status_bar_tips()
                } else {
                    None
                };
                debug!("Hint: {:?}", hint);
                model.status_bar_tips = hint;
            }
            for (index, layer) in stack.iter_mut().enumerate() {
                layer.render(&body_rect, frame, &model, index == last_index);
            }
            // render status bar
            self.status_bar
                .render(&statusbar_rect, frame, &model, false);
        });
    }

    fn invalidate(&mut self) {
        self.action_tx
            .send(Action::new("app", UiActions::Redraw))
            .unwrap();
    }

    /// Push a non-dismissable system message box onto every tab's layer stack
    /// to indicate that the IPC connection to EVE is being established.
    /// No-op if the popup is already shown.
    pub fn show_connection_popup(&mut self, message: &str) {
        if self.connection_popup_shown {
            return;
        }
        info!("Showing connection popup on all tabs");
        for stack in self.views.iter_mut() {
            let popup = create_system_message_box(" EVE Connection ", message);
            stack.push(Box::new(popup));
        }
        self.connection_popup_shown = true;
    }

    /// Pop the connection popup from every tab's layer stack.
    /// No-op if the popup is not currently shown.
    pub fn dismiss_connection_popup(&mut self) {
        if !self.connection_popup_shown {
            return;
        }
        info!("Dismissing connection popup from all tabs");
        for stack in self.views.iter_mut() {
            stack.pop();
        }
        self.connection_popup_shown = false;
    }

    pub fn handle_event(&mut self, event: Event) -> Option<Action> {
        if event != Event::Tick {
            debug!("Ui handle_event {:?}", event);
        }

        match event {
            // only for debugging purposes
            Event::Key(key)
                if (key.code == KeyCode::Char('e'))
                    && (key.modifiers == KeyModifiers::CONTROL)
                    && cfg!(debug_assertions) =>
            {
                debug!("CTRL+q: application Quit requested");
                self.action_tx
                    .send(Action::new("user", UiActions::Quit))
                    .unwrap();
            }
            // For debugging purposes
            Event::Key(key)
                if (key.code == KeyCode::Char('r'))
                    && (key.modifiers == KeyModifiers::CONTROL)
                    && cfg!(debug_assertions) =>
            {
                debug!("CTRL+r: manual Redraw requested");
                self.invalidate();
            }
            // For debugging purposes
            Event::Key(key)
                if (key.code == KeyCode::Char('p'))
                    && (key.modifiers == KeyModifiers::CONTROL)
                    && cfg!(debug_assertions) =>
            {
                debug!("CTRL+p: manual layer.pop() requested");
                self.pop_layer();
            }

            // For debugging purposes
            Event::Key(key)
                if (key.code == KeyCode::Char('a'))
                    && (key.modifiers == KeyModifiers::CONTROL)
                    && cfg!(debug_assertions) =>
            {
                debug!("CTRL+a: manual panic requested");
                panic!("Manual panic requested");
            }

            // forward all other key events to the top layer
            Event::Key(key) => {
                if let Some(action) = self.views[self.selected_tab as usize]
                    .last_mut()?
                    .handle_event(Event::Key(key))
                {
                    match action.action {
                        UiActions::DismissDialog => {
                            self.pop_layer();
                        }

                        UiActions::ButtonClicked(name) => match name.as_str() {
                            "Ok" => {
                                self.pop_layer();
                            }
                            "Cancel" => {
                                self.pop_layer();
                            }
                            _ => {}
                        },

                        _ => {
                            return Some(action);
                        }
                    }
                }

                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Left {
                    debug!("CTRL+Left: switching tab view");
                    self.selected_tab = self.selected_tab.previous();
                }

                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Right {
                    debug!("CTRL+Right: switching tab view");
                    self.selected_tab = self.selected_tab.next();
                }
            }
            Event::Tick => {
                // forward tick event to all layers. Collect actions
                for layer in self.views[self.selected_tab as usize].iter_mut() {
                    if let Some(action) = layer.handle_event(Event::Tick) {
                        self.action_tx.send(action).unwrap();
                    }
                }
                // and to the status bar
                self.status_bar.handle_event(Event::Tick);
            }
            _ => {
                debug!("Unhandled event: {:?}", event);
            }
        }

        None
    }

    fn push_layer(&mut self, d: impl IWindow + 'static) {
        self.views[self.selected_tab as usize].push(Box::new(d))
    }

    pub fn pop_layer(&mut self) -> Option<Box<dyn IWindow>> {
        self.views[self.selected_tab as usize].pop()
    }

    pub fn show_ip_dialog(&mut self, iface: NetworkInterfaceStatus) {
        let d = create_ip_dialog(&iface);
        self.push_layer(d);
    }

    pub fn show_server_url_dialog(&mut self, url: &str) {
        let d = create_input_dialog(
            "Change server URL",
            "Server URL",
            url,
            "https://prod.zedcontrol.zededa.net",
        );
        self.push_layer(d);
    }

    pub fn message_box(&mut self, title: &str, message: &str) {
        let d = super::message_box::create_message_box(title, message);
        self.push_layer(d);
    }
}

impl UiTabs {
    fn to_tab_title(self) -> Line<'static> {
        let text = self.to_string();
        format!(" {text} ").bg(Color::Black).into()
    }

    /// Get the previous tab, if there is no previous tab return the current tab.
    fn previous(self) -> Self {
        let current_index: usize = self as usize;
        let previous_index = current_index.saturating_sub(1);
        Self::from_repr(previous_index).unwrap_or(self)
    }

    /// Get the next tab, if there is no next tab return the current tab.
    fn next(self) -> Self {
        let current_index = self as usize;
        let next_index = current_index.saturating_add(1);
        Self::from_repr(next_index).unwrap_or(self)
    }
}
