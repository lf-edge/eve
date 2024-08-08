/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use cursive::Cursive;
use cursive::align::HAlign;
use cursive::views::{Dialog, SelectView, TextView};
use cursive::traits::*;

const VALID_FS: [&'static str; 3] = ["EXT3", "EXT4", "ZFS"];

pub fn choose_fs(s: &mut Cursive) {
    let mut select = SelectView::new()
        // Center the text horizontally
        .h_align(HAlign::Center)
        // Use keyboard to jump to the pressed letters
        .autojump();

    select.add_all_str(VALID_FS.join(" "));
    // Sets the callback for when "Enter" is pressed.
    select.set_on_submit(show_next_window);

    // Let's add a ResizedView to keep the list at a reasonable size
    // (it can scroll anyway).
    s.add_layer(
        Dialog::around(select.scrollable().fixed_size((20, 10)))
            .title("Where are you from?"),
    );

    s.run(true);
}

// Let's put the callback in a separate function to keep it clean,
// but it's not required.
fn show_next_window(siv: &mut Cursive, fs: &str) {
    siv.pop_layer();
    let text = format!("{} Selected!", fs);
    siv.add_layer(
        Dialog::around(TextView::new(text)).button("Quit", |s| s.quit()),
    );
}
