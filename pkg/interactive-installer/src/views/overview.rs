/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::HashMap;
use crate::data::OVERVIEW;

use cursive::{
    traits::Nameable,
    view::Resizable,
    views::{ListView, NamedView, ResizedView, TextView},
};

type Overview = ResizedView<NamedView<ListView>>;

pub fn get_overview(map: HashMap<String, String>) -> Overview {
    let mut l = ListView::new();

    // Convert map into a vector to stort it
    let mut sorted_map: Vec<(&String, &String)> = map.iter().collect();
    // Sort by values
    sorted_map.sort_by(|a, b| a.1.cmp(b.1));

    for (k, v) in sorted_map {
        if k == "INIT" {
            continue
        }
        // If v is empty set it to " "
        let v = if v.is_empty() { " " } else { &v };
        l.add_child(k, TextView::new(v));
    }
    l.with_name(OVERVIEW).full_height()
}
