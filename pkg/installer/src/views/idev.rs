/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::HashMap;

use crate::{
    data::{INSTALL_DISK},
    herr,
    utils::{get_block_devices, save_config_value},
};

use cursive::{
    align::HAlign,
    traits::Nameable,
    view::{Resizable, Scrollable},
    views::{Dialog, NamedView, ResizedView, SelectView},
};

type IDEVView = ResizedView<NamedView<Dialog>>;

pub fn get_idev(map: HashMap<String, String>) -> IDEVView {
    let title = "Choose installation disk";
    let idev = map.get(INSTALL_DISK).unwrap().clone();
    let mut selected: usize = 0;

    let mut bv: SelectView<String> = SelectView::new().h_align(HAlign::Center).autojump();
    let mut i = 0;

    let devices = get_block_devices();
    for d in devices.unwrap() {
        if d == idev {
            selected = i;
        }
        bv.add_item(d.clone(), d.clone());
        i += 1;
    }

    let d = Dialog::new().title(title).content(
        bv.selected(selected)
            .on_submit(move |s, v| herr!(s, save_config_value, INSTALL_DISK, v, true))
            .scrollable()
            .fixed_width(10),
    );
    d.with_name(INSTALL_DISK).full_height()

}
