// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    cell::LazyCell,
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use crate::{
    device::network::NetworkInterfaceStatus,
    events::Event::{self, Key},
    traits::{IAction, IEventHandler, IWindow},
    ui::{action::UiActions, focus_tracker::FocusMode, widgets::button::ButtonElement},
};
use crossterm::event::{KeyCode, KeyModifiers};
use log::{debug, error};
use ratatui::{
    layout::{Constraint, Flex, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::Line,
    widgets::{Block, BorderType, Borders, Clear, Tabs, Widget},
    Frame,
};
use strum::{Display, EnumCount, EnumIter, FromRepr, IntoEnumIterator};

use crate::{
    traits::IPresenter,
    ui::{focus_tracker::FocusTracker, window::LayoutMap},
};

use super::{
    action::Action,
    activity::Activity,
    widgets::{input_field::InputFieldElement, spin_box::SpinBoxElement},
    window::WidgetMap,
};

const NUM_FIELDS: usize = 5;

pub struct NetworkDialog {
    focus: FocusTracker,
    selected_tab: NetworkTabs,
    layout: LayoutMap,
    old_rect: Rect,
    page_widgets: WidgetMap,
    tab_widgets: HashMap<NetworkTabs, WidgetMap>,
    spinbox_state: HashMap<NetworkTabs, usize>,
    interface_name: String,
    ip: String,
    gw: String,
}

#[derive(
    Default, Copy, Clone, Display, EnumIter, Debug, FromRepr, EnumCount, Hash, Eq, PartialEq,
)]
enum NetworkTabs {
    #[default]
    IP,
    Proxy,
}

const window_focus_order: LazyCell<Vec<String>> =
    LazyCell::new(|| vec!["ok".to_string(), "cancel".to_string()]);

impl NetworkDialog {
    pub fn new(data: NetworkInterfaceStatus) -> Self {
        let mut page_widgets = WidgetMap::new();
        page_widgets.insert("ok".to_string(), Box::new(ButtonElement::new("ok")));
        page_widgets.insert("cancel".to_string(), Box::new(ButtonElement::new("cancel")));

        let mut ip_fields = WidgetMap::new();

        let mode = if data.is_dhcp { 1 } else { 0 };

        ip_fields.insert(
            "mode".to_string(),
            Box::new(SpinBoxElement::new(vec!["static", "DHCP"]).selected(mode)),
        );

        // find first ipv4 address
        let ip = data
            .ipv4
            .map(|i| i.first().map(|g| g.to_string()).unwrap_or("".to_string()))
            .unwrap_or("".to_string());
        let gw = data.gw.map(|f| f.to_string()).unwrap_or("".to_string());

        ip_fields.insert(
            "ip".to_string(),
            Box::new(InputFieldElement::new("IP", Some(ip.as_str()))),
        );
        ip_fields.insert(
            "gateway".to_string(),
            Box::new(InputFieldElement::new("Gateway", Some(gw.as_str()))),
        );
        ip_fields.insert(
            "dns".to_string(),
            Box::new(InputFieldElement::new("DNS", Some(&"".to_string()))),
        );
        ip_fields.insert(
            "ip-domain".to_string(),
            Box::new(InputFieldElement::new("Domain", Some(&"".to_string()))),
        );

        let mut proxy_fields = WidgetMap::new();
        proxy_fields.insert(
            "mode".to_string(),
            Box::new(SpinBoxElement::new(vec!["manual", "automatic"])),
        );
        proxy_fields.insert(
            "proxy-http".to_string(),
            Box::new(InputFieldElement::new("HTTP", Some(&"".to_string()))),
        );
        proxy_fields.insert(
            "proxy-https".to_string(),
            Box::new(InputFieldElement::new("HTTPS", Some(&"".to_string()))),
        );
        proxy_fields.insert(
            "socks".to_string(),
            Box::new(InputFieldElement::new("Socks", Some(&"".to_string()))),
        );
        proxy_fields.insert(
            "proxy-domain".to_string(),
            Box::new(InputFieldElement::new("Domain", Some(&"".to_string()))),
        );

        let mut focus_order: Vec<String> = window_focus_order.clone();
        let mut ip_focus_order: Vec<String> =
            ip_fields.keys().into_iter().map(|s| (*s).clone()).collect();
        focus_order.append(&mut ip_focus_order);

        let focus = FocusTracker::create_from_taborder(
            focus_order,
            Some("mode".to_string()),
            FocusMode::Wrap,
        );

        let mut tab_widgets = HashMap::new();
        tab_widgets.insert(NetworkTabs::IP, ip_fields);
        tab_widgets.insert(NetworkTabs::Proxy, proxy_fields);

        let mut spinbox_state = HashMap::new();
        NetworkTabs::iter().for_each(|i| {
            let state = if i == NetworkTabs::IP { mode } else { 0 };
            spinbox_state.insert(i, state);
            ()
        });

        Self {
            focus,
            layout: HashMap::new(),
            old_rect: Rect::ZERO,
            page_widgets,
            tab_widgets,
            selected_tab: NetworkTabs::IP,
            interface_name: data.name,
            spinbox_state,
            ip: "".to_string(),
            gw: "".to_string(),
        }
    }

    fn update_focus_order(&mut self) {
        let mut tab_order = window_focus_order.clone();
        self.tab_widgets[&self.selected_tab]
            .keys()
            .into_iter()
            .for_each(|key| tab_order.push(key.clone()));
        self.focus.set_tab_order(tab_order);
    }

    fn do_layout(&mut self, area: Rect) {
        if self.old_rect == area {
            return;
        }
        let [tabs, mode, fields, buttonbar] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Fill(0),
            Constraint::Length(3),
        ])
        .margin(1)
        .areas(area);

        let mut lm = LayoutMap::new();

        let _ = lm.insert("tabs".to_string(), tabs);
        let _ = lm.insert("mode".to_string(), mode);
        let _ = lm.insert("fields".to_string(), fields);

        let [ok, cancel] = Layout::horizontal(vec![Constraint::Length(10); 2])
            .flex(Flex::Start)
            .areas(buttonbar);

        let _ = lm.insert("ok".to_string(), ok);
        let _ = lm.insert("cancel".to_string(), cancel);

        let field_rects: [Rect; NUM_FIELDS] =
            Layout::vertical(vec![Constraint::Length(3); NUM_FIELDS]).areas(fields);
        field_rects.iter().enumerate().for_each(|(i, f)| {
            lm.insert(i.to_string(), *f);
            ()
        });

        lm.insert("ip".to_string(), field_rects[0]);
        lm.insert("gateway".to_string(), field_rects[1]);
        lm.insert("dns".to_string(), field_rects[2]);
        lm.insert("ip-domain".to_string(), field_rects[3]);
        lm.insert("proxy-http".to_string(), field_rects[0]);
        lm.insert("proxy-https".to_string(), field_rects[1]);
        lm.insert("socks".to_string(), field_rects[2]);
        lm.insert("proxy-domain".to_string(), field_rects[3]);

        self.layout = lm;
    }

    fn render_main(&mut self, area: &Rect, frame: &mut Frame) {
        let area = area.inner(Margin::new(8, 5));
        self.do_layout(area);
        Clear.render(area, frame.buffer_mut());
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::White))
            .style(Style::default().bg(Color::Black))
            .title(self.interface_name.as_str());

        block.render(area, frame.buffer_mut());

        frame.render_widget(
            tabs().select(self.selected_tab as usize),
            self.layout["tabs"],
        );

        self.page_widgets.iter_mut().for_each(|(name, field)| {
            field.render(
                &self.layout[name],
                frame,
                name.eq(&self.focus.get_focused_view().unwrap()),
            )
        });

        for (name, field) in self
            .tab_widgets
            .get_mut(&self.selected_tab)
            .unwrap()
            .iter_mut()
        {
            field.render(
                &self.layout[name],
                frame,
                name.eq(&self.focus.get_focused_view().unwrap()),
            );
            if *name == "mode" && self.spinbox_state[&self.selected_tab] == 1 {
                return;
            }
        }
    }
}

impl IPresenter for NetworkDialog {
    fn render(
        &mut self,
        area: &Rect,
        frame: &mut Frame<'_>,
        _model: &std::rc::Rc<crate::model::Model>,
        _focused: bool,
    ) {
        self.render_main(area, frame)
    }
}
impl IWindow for NetworkDialog {}
impl IEventHandler for NetworkDialog {
    fn handle_event(&mut self, event: Event) -> Option<Action> {
        match event {
            Key(key) => {
                debug!("netconf edit dialog handling {:?}", key);

                if key.code == KeyCode::Esc {
                    return Some(Action::new("edit network", UiActions::DismissDialog));
                }

                if let Some(redraw) = self.focus.handle_key_event(key) {
                    return Some(Action::new("edit network", redraw));
                }

                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Left {
                    debug!("CTRL+Left: switching tab view");
                    self.selected_tab = self.selected_tab.previous();
                    self.update_focus_order();
                    return Some(Action::new("edit network", UiActions::Redraw));
                }

                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Right {
                    debug!("CTRL+Right: switching tab view");
                    self.selected_tab = self.selected_tab.next();
                    self.update_focus_order();
                    return Some(Action::new("edit network", UiActions::Redraw));
                }

                debug!("key pressed {:?}", key);
                let focus = self.focus.get_focused_view()?;
                debug!("focused view {}", focus);
                if let Some(widget) = self.page_widgets.get_mut(&focus) {
                    if let Some(activity) = widget.handle_key_event(key) {
                        let widget_action = activity.try_into_action("edit network");
                        debug!("WID AC {:?}", widget_action);
                        if let Some(action) = widget_action {
                            match &action.action {
                                UiActions::ButtonClicked(name) => match name.as_str() {
                                    "ok" => {
                                        return Some(Action::new(
                                            "edit network",
                                            UiActions::UpdateIP {
                                                iface: self.interface_name.clone(),
                                                ip: self.ip.clone(),
                                                gw: self.gw.clone(),
                                            },
                                        ));
                                    }
                                    "cancel" => {
                                        return Some(Action::new(
                                            "edit network",
                                            UiActions::DismissDialog,
                                        ));
                                    }
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                    }
                } else {
                    error!("Active widget {} not found", focus);
                }

                let tab_widgets = &mut self.tab_widgets.get_mut(&self.selected_tab)?;

                let widget = tab_widgets.get_mut(&focus)?;
                let activity = widget.handle_key_event(key)?;
                debug!("action returned");
                match activity.try_into_uiaction()? {
                    UiActions::SpinBox { selected } => {
                        self.spinbox_state.insert(self.selected_tab, selected);
                        debug!("updated spinbox_state {selected}");
                        None
                    }
                    UiActions::Input { text } => {
                        debug!("SOURCE: {} text {}", focus, text);
                        match focus.as_str() {
                            "ip" => self.ip = text,
                            "gateway" => self.gw = text,
                            _ => {}
                        }
                        None
                    }

                    other => Some(Action::new("edit network", other)),
                }
            }
            Event::Tick | Event::TerminalResize(_, _) => None,
        }
    }
}

fn tabs() -> Tabs<'static> {
    let tab_titles = NetworkTabs::iter().map(NetworkTabs::to_tab_title);
    Tabs::new(tab_titles)
        .highlight_style(Modifier::REVERSED)
        .divider(" ")
        .padding("", "")
}

impl NetworkTabs {
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
