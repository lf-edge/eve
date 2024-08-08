/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::{data::RAID, herr, utils::save_config_value};

use cursive::{
    traits::Nameable,
    view::Resizable,
    views::{Dialog, NamedView, ResizedView, SelectView},
};

type RaidView = ResizedView<NamedView<Dialog>>;

fn get_raid_index(value: &str) -> usize {
    match value {
        "No raid" => usize::MAX,
        "raid1" => 0,
        "raid5" => 1,
        "raid6" => 2,
        &_ => 0,
    }
}

pub fn get_raid(raid: String, fs: String) -> RaidView {
    let key = "Choose RAID";
    let mut sel_view = SelectView::new()
        .on_submit(move |s, v| herr!(s, save_config_value, RAID, v, true));
    if fs == "ZFS" {
        sel_view.add_item("raid1", "raid1");
        sel_view.add_item("raid5", "raid5");
        sel_view.add_item("raid6", "raid6");
        sel_view.set_selection(get_raid_index(&raid));
    } else {
        sel_view.add_item("No raid", "");
    }
    let d = Dialog::new().title(key).content(
        sel_view
    );
    d.with_name(RAID).full_height()
}
