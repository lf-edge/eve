/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use cursive::views::{LinearLayout, TextView};
use serde_json::{Value};

use crate::{
    actions::execute,
    data::{Data, FS, INTERACTIVE_MODE, LABELS},
    state::{CurrentState, GlobalState, Move},
    views::{ctrl_buttons::buttons, fs_select::get_fs},
};

pub fn config(in_json: Value) {
    let mut c = cursive::CursiveRunnable::new(|| {
        cursive::backends::crossterm::Backend::init_with_stdout_file(std::fs::File::create(
            "/dev/stdout",
        )?)
    });
    let data = Data::new(in_json);
    if data.map.get(INTERACTIVE_MODE).unwrap_or(&"false".to_string()) == "false" {
        return;
    }

    let state = GlobalState {
        data,
        current_state: CurrentState::INIT,
    };

    c.set_user_data(state.clone());

    c.add_fullscreen_layer(
        LinearLayout::vertical()
            .child(TextView::new("Installer"))
            .child(get_fs(state.data.map.get(FS).unwrap().clone()))
            .child(buttons(false)),
    );

    let datamap = state.data.map.clone();
    for label in LABELS.iter() {
        let v = datamap.get(*label).unwrap();
        if v != "" {
            let _res = execute(&mut c, Move::Next);
        } else {
            break;
        }
    }

    c.run()
}

pub fn run() {
    println!("Installing EVE");
}
