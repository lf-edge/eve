// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::rc::Rc;

use crossterm::event::{KeyCode, KeyModifiers};
use log::{debug, info};
use ratatui::{
    layout::{Alignment, Constraint, Layout},
    prelude::Rect,
    style::{Color, Style, Stylize},
    text::{Line, Span, Text, ToText},
    widgets::{Block, BorderType, Borders, Cell, Padding, Row, Table},
    Frame,
};

use crate::{
    events::Event,
    ipc::eve_types::{AttestState, ZedAgentStatus},
    model::model::{Model, OnboardingStatus, VaultStatus},
    traits::{IEventHandler, IPresenter, IWindow},
    ui::action::{Action, UiActions},
};

use super::networkpage::{
    CTRL_STATUS_LENGTH, IFACE_LABEL_LENGTH, IPV6_MAX_LENGTH, LINK_STATE_LENGTH, MAC_LENGTH,
};

#[derive(Default)]
pub struct SummaryPage {
    attestation_state: String,
    last_attest_error: String,
}

impl SummaryPage {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    fn set_attestation_status(&mut self, z: &ZedAgentStatus) {
        match z.attest_state {
            AttestState::StateNone => {
                self.attestation_state = "Attestation not yet started".into();
                self.last_attest_error = "".into();
            }
            AttestState::StateAttestWait
            | AttestState::StateAttestEscrowWait
            | AttestState::StateInternalQuoteWait => {
                self.attestation_state = "Attestation in progress...".into();
            }
            AttestState::StateRestartWait => {
                self.attestation_state = "Attestation Restarted...".into();
                if !z.attest_error.is_empty() && self.last_attest_error != z.attest_error {
                    self.last_attest_error = z.attest_error.clone();
                }
            }
            AttestState::StateComplete => {
                self.attestation_state = "Complete".into();
                self.last_attest_error = "".into();
            }
            _ => {
                if !z.attest_error.is_empty() && self.last_attest_error != z.attest_error {
                    self.last_attest_error = z.attest_error.clone();
                }
            }
        }
    }

    pub fn update_attestation_state(&mut self, model: &Rc<Model>) {
        let model = model.borrow();
        let vault_status = &model.vault_status;

        if !vault_status.is_vault_locked() {
            self.attestation_state = String::new();
            self.last_attest_error = String::new();
            return;
        }

        if let Some(z) = &model.z_status {
            self.set_attestation_status(z);
        }
    }
}

impl IWindow for SummaryPage {
    fn status_bar_tips(&self) -> Option<String> {
        Some(format!(
            "Alt + ◄ ► linux terminal | Ctrl + s change server | Ctrl + ◄ ► switch tabs"
        ))
    }
}

impl IEventHandler for SummaryPage {
    fn handle_event(&mut self, event: crate::events::Event) -> Option<super::action::Action> {
        // handle Ctrl+s to change the server
        match event {
            Event::Key(key)
                if (key.code == KeyCode::Char('s')) && (key.modifiers == KeyModifiers::CONTROL) =>
            {
                debug!("CTRL+s: server change requested");
                return Some(Action::new("net", UiActions::ChangeServer));
            }
            _ => {}
        }
        None
    }
}

impl IPresenter for SummaryPage {
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, model: &Rc<Model>, _focused: bool) {
        self.update_attestation_state(model);

        let [server, onboarding_status_and_app_sunnary_rect, vault_attest_status_rect, network_summary_rect] =
            Layout::vertical(vec![
                Constraint::Length(3),
                Constraint::Length(6),
                Constraint::Length(7),
                Constraint::Fill(1),
            ])
            .areas(*area);

        let [onboarding_status_rect, app_summary_rect] =
            Layout::horizontal(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(onboarding_status_and_app_sunnary_rect);

        let [vault_status_rect, attest_status_rect] =
            Layout::horizontal(vec![Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(vault_attest_status_rect);

        let server_url = ratatui::widgets::Paragraph::new(
            model
                .borrow()
                .node_status
                .server
                .clone()
                .unwrap_or("N/A".to_string()),
        )
        .block(
            ratatui::widgets::Block::default()
                .borders(ratatui::widgets::Borders::ALL)
                .title("Server (CTRL+s to change)"),
        )
        .style(ratatui::style::Style::default().fg(ratatui::style::Color::White));
        frame.render_widget(server_url, server);

        self.render_onboarding_status(model, frame, onboarding_status_rect);
        self.render_app_summary(model, frame, app_summary_rect);

        self.render_vault_status(model, frame, vault_status_rect);
        self.render_attestation_status(model, frame, attest_status_rect);
        self.render_connection_summary(model, frame, network_summary_rect);
    }
}

impl SummaryPage {
    fn render_onboarding_status(
        &self,
        model: &Rc<Model>,
        frame: &mut Frame<'_>,
        onboarding_status_rect: Rect,
    ) {
        let onboarding_status = model.borrow().node_status.onboarding_status.clone();
        let mut text = Vec::new();
        let mut spans = vec![];
        spans.push(Span::styled("status: ", Style::default().fg(Color::White)));
        spans.push(match onboarding_status {
            OnboardingStatus::Unknown => {
                Span::styled("Checking...", Style::default().fg(Color::Yellow))
            }
            OnboardingStatus::Onboarding => {
                Span::styled("Onboarding...", Style::default().fg(Color::Yellow))
            }
            OnboardingStatus::Onboarded(_) => {
                Span::styled("Onboarded", Style::default().fg(Color::Green))
            }
            OnboardingStatus::Error(_) => Span::styled("Error", Style::default().fg(Color::Red)),
        });

        text.push(Line::from(spans));

        match onboarding_status {
            OnboardingStatus::Unknown => {
                text.push(Line::from(vec![
                    Span::styled("GUID: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Yellow)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Green)),
                ]));
            }
            OnboardingStatus::Onboarding => {
                text.push(Line::from(vec![
                    Span::styled("GUID: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Yellow)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Green)),
                ]));
            }
            OnboardingStatus::Onboarded(guid) => {
                text.push(Line::from(vec![
                    Span::styled("GUID: ", Style::default().fg(Color::White)),
                    Span::styled(format!("{}", guid), Style::default().fg(Color::White)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Green)),
                ]));
            }
            OnboardingStatus::Error(err) => {
                text.push(Line::from(vec![
                    Span::styled("GUID: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Yellow)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::White)),
                    Span::styled(err, Style::default().fg(Color::Red)),
                ]));
            }
        }

        let onboarding_status = ratatui::widgets::Paragraph::new(Text::from(text))
            .block(
                ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .title("Onboarding status"),
            )
            .style(ratatui::style::Style::default().fg(ratatui::style::Color::White));
        frame.render_widget(onboarding_status, onboarding_status_rect);
    }

    fn render_app_summary(&self, model: &Rc<Model>, frame: &mut Frame<'_>, app_summary_rect: Rect) {
        let apps = &model.borrow().node_status.app_summary;

        let mut app_summary_text = vec![];
        app_summary_text.push(Line::from(vec![
            Span::raw("Running:  "),
            Span::styled(
                format!("{}", apps.total_running),
                Style::default().fg(Color::Green),
            ),
        ]));
        app_summary_text.push(Line::from(vec![
            Span::raw("Starting: "),
            Span::styled(
                format!("{}", apps.total_starting),
                Style::default().fg(Color::Green),
            ),
        ]));
        app_summary_text.push(Line::from(vec![
            Span::raw("Stopping: "),
            Span::styled(
                format!("{}", apps.total_stopping),
                Style::default().fg(Color::Yellow),
            ),
        ]));
        app_summary_text.push(Line::from(vec![
            Span::raw("In error: "),
            Span::styled(
                format!("{}", apps.total_error),
                Style::default().fg(Color::Red),
            ),
        ]));
        let app_summary = ratatui::widgets::Paragraph::new(Text::from(app_summary_text))
            .block(
                ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .title("App summary"),
            )
            .style(ratatui::style::Style::default().fg(ratatui::style::Color::White));
        frame.render_widget(app_summary, app_summary_rect);
    }

    fn render_vault_status(&self, model: &Rc<Model>, frame: &mut Frame<'_>, status_rect: Rect) {
        let model = model.borrow();
        let vault_status = &model.vault_status;
        // let z_status = &model.z_status;
        let mut text = Vec::new();
        let mut spans = vec![];
        spans.push(Span::styled("Status: ", Style::default().fg(Color::White)));
        spans.push(match vault_status {
            VaultStatus::Unknown => Span::styled("Unknown", Style::default().fg(Color::Yellow)),
            VaultStatus::EncryptionDisabled(_, _) => {
                Span::styled("Encryption disabled", Style::default().fg(Color::Yellow))
            }
            VaultStatus::Unlocked(_) => Span::styled("Unlocked", Style::default().fg(Color::Green)),
            VaultStatus::Locked(_, _) => Span::styled("Locked", Style::default().fg(Color::Red)),
        });

        text.push(Line::from(spans));

        match vault_status {
            VaultStatus::Unknown => {
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Green)),
                ]));
            }
            VaultStatus::EncryptionDisabled(reason, tpm_used) => {
                text.push(Line::from(vec![
                    Span::styled("TPM used: ", Style::default().fg(Color::White)),
                    if *tpm_used {
                        Span::styled("Yes", Style::default().fg(Color::Green))
                    } else {
                        Span::styled("No", Style::default().fg(Color::Red))
                    },
                ]));
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::Red)),
                    Span::styled(&reason.error, Style::default().fg(Color::White)),
                ]));
            }
            VaultStatus::Unlocked(tpm_used) => {
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::White)),
                    Span::styled("N/A", Style::default().fg(Color::Green)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("TPM used: ", Style::default().fg(Color::White)),
                    if *tpm_used {
                        Span::styled("Yes", Style::default().fg(Color::Green))
                    } else {
                        Span::styled("No", Style::default().fg(Color::Red))
                    },
                ]));
            }
            VaultStatus::Locked(err, pcr) => {
                text.push(Line::from(vec![
                    Span::styled("Affected PCRs: ", Style::default().fg(Color::White)),
                    if let Some(pcr) = pcr {
                        let pcr = pcr
                            .iter()
                            .map(|p| format!("{:?}", p))
                            .collect::<Vec<String>>()
                            .join(",");
                        Span::styled(format!("{}", pcr), Style::default().fg(Color::Green))
                    } else {
                        Span::styled("N/A", Style::default().fg(Color::Yellow))
                    },
                ]));
                text.push(Line::from(vec![
                    Span::styled("Error: ", Style::default().fg(Color::Red)),
                    Span::styled(&err.error, Style::default().fg(Color::White)),
                ]));
                text.push(Line::from(vec![
                    Span::styled("Switch to ", Style::default().fg(Color::White)),
                    Span::styled("Vault ", Style::default().fg(Color::Green)),
                    Span::styled(
                        "tab for more information",
                        Style::default().fg(Color::White),
                    ),
                ]));
                // look at attestation status
                // Basically we need to
                // 1. show last attestation error
                // 2. attestation will go through following states Wait -> InternalQuoteWait -> RestartWait -> Complete
                // and some other. Show minimal information to the user
                // text.push(Line::from(vec![
                //     Span::styled("Attest: ", Style::default().fg(Color::Red)),
                //     Span::styled(&self.attestation_state, Style::default().fg(Color::White)),
                // ]));
                // text.push(Line::from(vec![
                //     Span::styled("Attest error: ", Style::default().fg(Color::Red)),
                //     Span::styled(&self.last_attest_error, Style::default().fg(Color::White)),
                // ]));
            }
        }

        // match z_status {
        //     Some(status) => {
        //         text.push(Line::from(vec![
        //             Span::styled("Attestation status: ", Style::default().fg(Color::White)),
        //             Span::styled(
        //                 format!("{:#?}", status.attest_state),
        //                 Style::default().fg(Color::Green),
        //             ),
        //         ]));
        //         text.push(Line::from(vec![
        //             Span::styled("Attestation error: ", Style::default().fg(Color::White)),
        //             Span::styled(
        //                 format!("{:#?}", status.attest_error),
        //                 Style::default().fg(Color::Green),
        //             ),
        //         ]));
        //         // is maintenance mode enabled
        //         text.push(Line::from(vec![
        //             Span::styled("Maintenance mode: ", Style::default().fg(Color::White)),
        //             Span::styled(
        //                 format!("{:#?}", status.maintenance_mode),
        //                 Style::default().fg(Color::Green),
        //             ),
        //         ]));
        //     }
        //     None => {}
        // }

        let vault_status_widget = ratatui::widgets::Paragraph::new(Text::from(text))
            .block(
                ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .title(" Vault "),
            )
            .style(ratatui::style::Style::default().fg(ratatui::style::Color::White));
        frame.render_widget(vault_status_widget, status_rect);
    }

    fn attestation_state(vault_status: &VaultStatus) -> String {
        match vault_status {
            VaultStatus::Unknown => "Checking...".into(),
            VaultStatus::EncryptionDisabled(_, _) => "Disabled".into(),
            VaultStatus::Unlocked(tpm) => {
                if *tpm {
                    "Enabled".into()
                } else {
                    "Disabled".into()
                }
            }
            VaultStatus::Locked(_, _) => "Enabled".into(),
        }
    }

    fn render_attestation_status(
        &self,
        model: &Rc<Model>,
        frame: &mut Frame<'_>,
        status_rect: Rect,
    ) {
        let model = model.borrow();
        let vault_status = &model.vault_status;
        let mut text = Vec::new();

        let attestation_state = Self::attestation_state(vault_status);
        let is_enabled = attestation_state == "Enabled";
        text.push(Line::from(vec![
            Span::styled("State: ", Style::default().fg(Color::White)),
            Span::styled(attestation_state, Style::default().fg(Color::Green)),
        ]));

        if is_enabled {
            if !self.attestation_state.is_empty() {
                text.push(Line::from(vec![
                    Span::styled("Current state: ", Style::default().fg(Color::White)),
                    Span::styled(&self.attestation_state, Style::default().fg(Color::White)),
                ]));
                if self.attestation_state != "Complete" {
                    // map error to user friendly text
                    let error = self.last_attest_error.replace("[ATTEST]", "");
                    let error = match error.trim() {
                        "Quote Mismatch" => {
                            if vault_status.is_vault_locked() {
                                "PCR quote mismatch and Vault is locked. You are connected to the controller. Fix device configuration or PCR template on the controller"
                                    .to_string()
                            } else {
                                "PCR quote mismatch but Vault is unlocked. You are connected to the controller. Fix PCR template on the controller"
                                .to_string()
                            }
                        }
                        e => e.to_string(),
                    };

                    if !error.is_empty() {
                        text.push(Line::from(vec![
                            Span::styled("Error: ", Style::default().fg(Color::Red)),
                            Span::styled(error, Style::default().fg(Color::White)),
                        ]));
                    }
                }
            }
        }

        let attest_status_widget = ratatui::widgets::Paragraph::new(Text::from(text))
            .wrap(ratatui::widgets::Wrap { trim: true })
            .block(
                ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .title(" Device Attestation "),
            )
            .style(ratatui::style::Style::default().fg(ratatui::style::Color::White));
        frame.render_widget(attest_status_widget, status_rect);
    }

    fn render_interface_list(&self, model: &Rc<Model>, list_rect: Rect, frame: &mut Frame) {
        // create header for the table
        let header = Row::new(vec![
            Cell::from("Name").style(Style::default()),
            Cell::from("Link").style(Style::default()),
            Cell::from("IPv4/IPv6").style(Style::default()),
            Cell::from("MAC").style(Style::default()),
            Cell::from("Controller").style(Style::default()),
        ]);

        // create list items from the interface
        let rows = model
            .borrow()
            .network
            .iter()
            .map(|iface| super::networkpage::info_row_from_iface(iface))
            .collect::<Vec<_>>();

        // create a surrounding block for the list
        let block = Block::default()
            .title(" Network Interfaces ")
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_type(BorderType::Plain)
            // .border_style(Style::default().fg(Color::White).bg(Color::Black))
            // .style(Style::default().bg(Color::Black));
            .padding(Padding::new(1, 1, 1, 1));

        // Create a List from all list items and highlight the currently selected one
        let list = Table::new(
            rows,
            [
                Constraint::Max(IFACE_LABEL_LENGTH),
                Constraint::Max(LINK_STATE_LENGTH),
                Constraint::Length(IPV6_MAX_LENGTH),
                Constraint::Max(MAC_LENGTH),
                Constraint::Length(CTRL_STATUS_LENGTH),
            ],
        )
        .block(block)
        .header(header);

        // StatefulWidget::render(list, list_rect, frame.buffer_mut(), &mut self.list.state);
        frame.render_widget(list, list_rect);
    }

    fn render_connection_summary(
        &self,
        model: &Rc<Model>,
        frame: &mut Frame<'_>,
        network_info_rect: Rect,
    ) {
        // render block in the whole rect
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Connectivity status")
            .border_type(BorderType::Plain)
            .border_style(Style::default().fg(Color::White).bg(Color::Black));
        // .style(Style::default().bg(Color::Black));
        frame.render_widget(block, network_info_rect);

        let inner_rect = network_info_rect.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 1,
        });

        let dpc_key = model
            .borrow()
            .dpc_key
            .clone()
            .unwrap_or("Configuration source unavailable".to_string());

        let configuration_string = match dpc_key.as_str() {
            "zedagent" => "Pushed from controller".green(),
            "manual" => "Set by local user".yellow(),
            "lastresort" => "Automatic DHCP (Last resort)".yellow(),
            s => s.red(),
        };

        // convert DPC key into human readabel piece of information
        let dpc_info = Line::default().spans(vec![
            "Current networking configuration: ".white(),
            configuration_string,
        ]);

        let mut text = Text::from(dpc_info);

        if dpc_key == "manual" {
            text.push_line(vec!["WARNING: ".yellow(),"the configuratiion set locally will be overwritten by working configuration from the controller".white()]);
        }

        // if we have no interfaces connected  to controller (all have errors), show the message
        if model
            .borrow()
            .network
            .iter()
            .all(|iface| !iface.is_connected())
        {
            text.push_line(vec![
                "WARNING: ".yellow(),
                "No interfaces connected to the controller. See ".white(),
                "Network".green(),
                " tab".white(),
            ]);
        }

        // get number of lines in text
        let lines = text.height();

        // split inner rect vertically into 2 parts
        let [network_summary_rect, iface_list_rect] =
            Layout::vertical(vec![Constraint::Length(lines as u16), Constraint::Fill(1)])
                .areas(inner_rect);

        // split iface list rect into 2 parts horizontally
        // let [iface_list_rect, _] =
        //     Layout::horizontal(vec![Constraint::Percentage(50), Constraint::Fill(1)])
        //         .areas(iface_list_rect);

        let connectivity_status_widget = ratatui::widgets::Paragraph::new(Text::from(text))
            .style(ratatui::style::Style::default().fg(ratatui::style::Color::White));
        frame.render_widget(connectivity_status_widget, network_summary_rect);
        self.render_interface_list(model, iface_list_rect, frame);
    }
}
