/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use serde_json::json;
use std::env;
use crate::utils::read_installer_json;
use anyhow::Result;

mod actions;
mod data;
mod error;
mod installer;
mod state;
mod utils;
mod views;

fn help() {
    println!(
        "Usage: tui-cursive <installer.json>
    input file <installer.json> is optional."
    );
}

fn main() -> Result<()>{
    let mut installer_json = json!(null);
    let args: Vec<String> = env::args().collect();

    match args.len() {
        // no arguments passed
        1 => {
            println!("Interactive installer mode!");
        }
        2 => {
            installer_json = read_installer_json(&args[1])?
        }
        // all the other cases
        _ => {
            // show a help message
            help();
        }
    }

    println!("Initializing EVE config!");
    installer::config(installer_json);
    installer::run();

    Ok(())
}
