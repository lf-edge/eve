/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::HashMap;

use crate::{
    data::{PERSIST_DISK},
    herr,
    utils::{get_block_devices, add_config_value, remove_config_value},
};

use cursive::{
    traits::Nameable,
    view::{Resizable, Scrollable},
    views::{Dialog, Checkbox, NamedView, ResizedView, ListView},
};

type PDEVView = ResizedView<NamedView<Dialog>>;

pub fn get_pdev(map: HashMap<String, String>) -> PDEVView {
    let title = "Choose persist disks";
    let pdevstring = map.get(PERSIST_DISK).unwrap().clone();
    // Split the string by the comma and trim whitespace from each part
    let pdevs: Vec<&str> = pdevstring.split(',')
                               .map(|s| s.trim())
                               .collect();

    let mut lv: ListView = ListView::new();
    //let mut i = 0;

    let devices = get_block_devices();
    for d in devices.unwrap() {
        let dev = d.clone();
        let mut c = Checkbox::new().on_change(move |s, checked | {
            if checked {
                herr!(s, add_config_value, PERSIST_DISK, &dev);
            } else if !checked {
                herr!(s, remove_config_value, PERSIST_DISK, &dev);
            }
        });
        if pdevs.contains(&d.as_str()) {
            c.set_checked(true);
        }
        lv.add_child(&d, c);
    }

    let d = Dialog::new().title(title).content(
        lv.fixed_width(10).
        scrollable(),
    );
    d.with_name(PERSIST_DISK).full_height()
}
