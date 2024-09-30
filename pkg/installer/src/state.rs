/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::fmt;

use crate::data::Data;

#[derive(Debug, Copy, Clone)]
pub enum CurrentState {
    INIT,
    FS,
    Raid,
    IDEV,
    PDEV,
    Config,
    Overview,
}

impl fmt::Display for CurrentState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl CurrentState {
    pub fn next(&self) -> Self {
        use CurrentState::*;
        match *self {
            INIT => IDEV,
            IDEV => FS,
            FS => Raid,
            Raid => PDEV,
            PDEV => Config,
            Config => Overview,
            Overview => Overview,
        }
    }

    pub fn prev(&self) -> Self {
        use CurrentState::*;
        match *self {
            INIT => INIT,
            IDEV => IDEV,
            Raid => IDEV,
            FS => Raid,
            PDEV => FS,
            Config => PDEV,
            Overview => Config,
        }
    }
}

pub enum Move {
    Previous,
    Next,
}

#[derive(Clone)]
pub struct GlobalState {
    pub data: Data,
    pub current_state: CurrentState,
}
