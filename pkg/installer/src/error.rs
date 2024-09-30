/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use cursive::{view::Resizable, views::Dialog, Cursive};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    // Could not get global state of application from Cursive
    NoState,

    IoError,
}

impl Error {
    pub fn show_dialog(self, c: &mut Cursive) {
        c.add_layer(
            Dialog::info(format!("{:?}", self))
                .title("ERROR")
                .full_screen(),
        );
    }
}

impl From<std::io::Error> for Error {
    fn from(_a: std::io::Error) -> Self {
        Self::IoError
    }
}
