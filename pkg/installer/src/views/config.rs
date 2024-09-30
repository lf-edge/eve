/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::HashMap;

use crate::{
    data::{
        CONFIG, CONSOLE, FIND_BOOT, INSTALL_SERVER, PAUSE_AFTER_INSTALL, PAUSE_BEFORE_INSTALL,
        REBOOT_AFTER_INSTALL, ROOT, SOFT_SERIAL,
    },
    herr,
    utils::save_config_value,
};

use cursive::{
    traits::Nameable,
    view::Resizable,
    views::{EditView, ListView, NamedView, ResizedView},
};

type ConfigView = ResizedView<NamedView<ListView>>;

pub fn get_config(map: HashMap<String, String>) -> ConfigView {
    let l = ListView::new()
        .child(
            INSTALL_SERVER,
            EditView::new()
                .content(map.get(INSTALL_SERVER).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(
                        s,
                        save_config_value,
                        INSTALL_SERVER,
                        v.to_string().as_str(),
                        false
                    )
                }),
        )
        .child(
            SOFT_SERIAL,
            EditView::new()
                .content(map.get(SOFT_SERIAL).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(
                        s,
                        save_config_value,
                        SOFT_SERIAL,
                        v.to_string().as_str(),
                        false
                    )
                }),
        )
        .child(
            REBOOT_AFTER_INSTALL,
            EditView::new()
                .content(map.get(REBOOT_AFTER_INSTALL).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(
                        s,
                        save_config_value,
                        REBOOT_AFTER_INSTALL,
                        v.to_string().as_str(),
                        false
                    )
                }),
        )
        .child(
            PAUSE_AFTER_INSTALL,
            EditView::new()
                .content(map.get(PAUSE_AFTER_INSTALL).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(
                        s,
                        save_config_value,
                        PAUSE_AFTER_INSTALL,
                        v.to_string().as_str(),
                        false
                    )
                }),
        )
        .child(
            PAUSE_BEFORE_INSTALL,
            EditView::new()
                .content(map.get(PAUSE_BEFORE_INSTALL).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(
                        s,
                        save_config_value,
                        PAUSE_BEFORE_INSTALL,
                        v.to_string().as_str(),
                        false
                    )
                }),
        )
        .child(
            ROOT,
            EditView::new()
                .content(map.get(ROOT).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(s, save_config_value, ROOT, v.to_string().as_str(), false)
                }),
        )
        .child(
            FIND_BOOT,
            EditView::new()
                .content(map.get(FIND_BOOT).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(
                        s,
                        save_config_value,
                        FIND_BOOT,
                        v.to_string().as_str(),
                        false
                    )
                }),
        )
        .child(
            CONSOLE,
            EditView::new()
                .content(map.get(CONSOLE).unwrap().clone())
                .on_edit(move |s, v, _| {
                    herr!(s, save_config_value, CONSOLE, v.to_string().as_str(), false)
                }),
        );
    l.with_name(CONFIG).full_height()
}
