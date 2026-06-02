// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ipc::eve_types::DownloaderStatus;
use crate::model::device::summary::DeviceSummary;
use ratatui::text::Line;
use ratatui::text::Text;
use ratatui::widgets::Block;
use ratatui::widgets::Gauge;
use ratatui::widgets::Wrap;
use std::rc::Rc;

use crate::events;
use crate::model::model::Model;
use crate::traits::{IEventHandler, IPresenter, IWindow};
use crate::ui::action::Action;
use crate::ui::window::LayoutMap;
use log::debug;
use ratatui::prelude::Constraint;
use ratatui::prelude::Layout;
use ratatui::prelude::Rect;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub struct HomePage {
    state: DeviceSummary,
    layout: Option<LayoutMap>,
    old_size: Rect,
}

impl HomePage {
    pub fn new() -> Self {

        HomePage {
            layout: None,
            state: DeviceSummary::dummy_summary(),
            old_size: Rect::ZERO,
        }
    }
    pub fn do_layout(&self, area: &Rect, _model: &Rc<Model>) -> LayoutMap {
        let [left, right] =
            Layout::horizontal([Constraint::Ratio(1, 3), Constraint::Ratio(2, 3)]).areas(*area);

        let [details, download] =
            Layout::vertical([Constraint::Fill(0), Constraint::Length(5)]).areas(left);

        let [usb, pci] =
            Layout::vertical([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).areas(right);

        let mut lm = LayoutMap::new();
        lm.insert("summary".to_string(), details);
        lm.insert("download".to_string(), download);
        lm.insert("usb".to_string(), usb);
        lm.insert("pci".to_string(), pci);
        lm
    }

    pub fn do_render(&mut self, area: &Rect, frame: &mut Frame<'_>, model: &Rc<Model>) {
        if self.layout.is_none() || self.old_size != *area {
            self.layout = Some(self.do_layout(area, model));
            self.old_size = *area;
        }
        let layout = self.layout.as_ref().unwrap();

        let left = Paragraph::new(Text::from(vec![
            Line::from(""),
            Line::from(format!("Name: {}", self.state.name)),
            Line::from(format!(
                "Last update: {}",
                self.state.last_checkin.format("%d-%m-%Y %H:%M %Z")
            )),
        ]))
        .block(Block::bordered().title("Device Summary"));
        frame.render_widget(left, layout["summary"]);

        self.render_download(layout["download"], frame, &model.borrow().downloader);

        let usb = Paragraph::new(Text::from(self.state.usb_devices.join("\n")))
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title("USB Devices"));
        frame.render_widget(usb, layout["usb"]);

        let pci = Paragraph::new(Text::from(self.state.pci_devices.join("\n")))
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title("PCI Devices"));
        frame.render_widget(pci, layout["pci"]);
    }

    fn render_download(&self, area: Rect, frame: &mut Frame<'_>, model: &Option<DownloaderStatus>) {
        let download = Block::bordered().title("Download status");
        frame.render_widget(&download, area);

        let Some(model) = model else {
            frame.render_widget(Line::raw("No download in progress"), download.inner(area));
            return;
        };

        let contents = download.inner(area);
        let [area_status, area_name, area_progress] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .areas(contents);

        let download_progress = Gauge::default().percent(model.progress as u16);
        frame.render_widget(Line::raw(format!("State: {}", model.state)), area_status);
        frame.render_widget(Line::raw(format!("File: {}", &model.name)), area_name);
        frame.render_widget(download_progress, area_progress);
    }
}

impl IPresenter for HomePage {
    // add code here
    fn render(&mut self, area: &Rect, frame: &mut Frame<'_>, model: &Rc<Model>, _: bool) {
        self.do_render(area, frame, model);
    }
    fn can_focus(&self) -> bool {
        false
    }
}

impl IEventHandler for HomePage {
    fn handle_event(&mut self, event: events::Event) -> Option<Action> {
        debug!("HomePage handle_event {:?}", event);
        None
    }
}

impl IWindow for HomePage {}
