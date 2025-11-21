/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use cursive::{
    align::HAlign, views::{LinearLayout, TextView}, Cursive
};

use crate::{
    data::{INIT, FS, RAID},
    error::Result,
    state::{CurrentState, GlobalState},
    utils::get_state_mut,
    views::{
        config::get_config, ctrl_buttons::buttons, fs_select::get_fs, idev::get_idev,
        overview::get_overview, pdev::get_pdev,
        raid::get_raid,
    },
};

use crate::state::Move;

fn new_state(state: GlobalState) -> (Box<dyn cursive::View + 'static>, bool) {
    let map = state.data.map.clone();
    match state.current_state {
        CurrentState::INIT => {
            return (Box::new(get_fs(map.get(INIT).unwrap().clone())), false);
        }
        CurrentState::FS => {
            return (Box::new(get_fs(map.get(FS).unwrap().clone())), false);
        }
        CurrentState::Raid => {
            return (Box::new(get_raid(map.get(RAID).unwrap().clone(), map.get(FS).unwrap().clone())), false);
        }
        CurrentState::IDEV => {
            return (Box::new(get_idev(map)), false);
        }
        CurrentState::PDEV => {
            return (Box::new(get_pdev(map)), false);
        }
        CurrentState::Config => {
            return (Box::new(get_config(map)), false);
        }
        CurrentState::Overview => {
            return (Box::new(get_overview(map)), true);
        }
    };
}

fn navigate(c: &mut Cursive, state: GlobalState) {
    let (view, final_state) = new_state(state);
    c.pop_layer();
    c.add_fullscreen_layer(
        LinearLayout::vertical()
            .child(TextView::new("Installer").h_align(HAlign::Center))
            .child(view)
            .child(buttons(final_state)),
    );
}

fn state_move(state: &mut GlobalState, m: Move) {
    match m {
        Move::Previous => {
            state.current_state = state.current_state.prev();
        }
        Move::Next => {
            state.current_state = state.current_state.next();
        }
    }
}

pub fn execute(c: &mut Cursive, m: Move) -> Result<()> {
    let mut state = get_state_mut(c)?;
    state_move(&mut state, m);
    c.set_user_data(state.clone());
    navigate(c, state);

    Ok(())
}
