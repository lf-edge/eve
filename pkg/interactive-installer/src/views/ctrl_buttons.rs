/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use cursive::{
    traits::Nameable,
    view::Resizable,
    views::{Button, ListView, NamedView, OnEventView, ResizedView},
    Cursive,
};

use crate::state::Move;
use crate::{
    actions::execute,
    data::{BUTTONS, INSTALLER_CFG_OUT},
    herr,
    state::GlobalState,
};

type CmdLine = OnEventView<ResizedView<NamedView<ListView>>>;

pub fn buttons(final_state: bool) -> CmdLine {
    let mut l = ListView::new().child(
        "Navigation",
        Button::new_raw("previous", |c| herr!(c, execute, Move::Previous)),
    );
    if final_state {
        l.add_child(
            "",
            Button::new_raw("finish", |c| herr!(c, write_config_and_quit)),
        );
    } else {
        l.add_child(
            "",
            Button::new_raw("next", |c| herr!(c, execute, Move::Next)),
        );
    }
    OnEventView::new(l.with_name(BUTTONS).full_width())
}

fn write_config_and_quit(c: &mut Cursive) -> crate::error::Result<()> {
    let mut d = c.take_user_data::<GlobalState>().unwrap().data;
    d.write(INSTALLER_CFG_OUT)?;
    c.quit();
    Ok(())
}
