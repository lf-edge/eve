/*
 * RBMenu - Rust Bookmark Manager
 * Copyright (C) 2021-2022 DevHyperCoder
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

pub mod bookmark;
pub mod bookmark_query;
pub mod commands;
pub mod config;
pub mod data;
pub mod error;
pub mod parser;

use commands::{insert, list, remove, update};
use config::{Config, SubOpt};
use data::read_data_file;

use error::Result;
use structopt::StructOpt;

/// Call command functions based on given options
pub fn run() -> Result<()> {
    let opts = Config::from_args();
    let mut data = read_data_file()?;

    match opts.sub_cmd {
        SubOpt::Insert { name, url } => insert(url, data, name)?,
        SubOpt::Remove { query } => {
            let removed = remove(&mut data, query)?;
            if removed.is_empty() {
                println!("Nothing to remove!");
                return Ok(());
            }
            println!("Removed: ");
            for i in removed {
                i.colored_fmt()
            }
        }
        SubOpt::List { query, show_link } => {
            let listed = list(&data, query)?;
            for i in listed {
                if show_link {
                    println!("{}", i.link);
                } else {
                    i.colored_fmt()
                }
            }
        }
        SubOpt::Update { query } => update(&mut data, query)?,
    }
    Ok(())
}
