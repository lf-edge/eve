/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use crate::{data::FS, herr, utils::save_config_value};

use cursive::{
    traits::Nameable,
    view::Resizable,
    views::{Dialog, NamedView, ResizedView, SelectView},
};

type FSView = ResizedView<NamedView<Dialog>>;

fn get_fs_index(value: &str) -> usize {
    match value {
        "EXT4" => 0,
        "ZFS" => 1,
        &_ => 0,
    }
}

pub fn get_fs(value: String) -> FSView {
    let title = "Choose persist FS";
    let d = Dialog::new().title(title).content(
        SelectView::new()
            .item("EXT4", "EXT4")
            .item("ZFS", "ZFS")
            .selected(get_fs_index(&value))
            .on_submit(move |s, v| herr!(s, save_config_value, FS, v, true))
            .fixed_width(10),
    );
    d.with_name(FS).full_height()
}
