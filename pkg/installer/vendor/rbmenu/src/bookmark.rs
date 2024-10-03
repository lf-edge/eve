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

use crate::parser::{get_domain_name, is_url};
use chrono::prelude::Local;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use substring::Substring;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Bookmark {
    pub is_file: bool,
    pub link: String,
    pub name: String,
    pub date: String,
    pub id: u32,
}

impl Bookmark {
    /// Generate a suitable name for Bookmark
    /// If name is empty or not provided, link is parsed to get the domain name.
    /// If name contains spaces, it is converted to underscores
    pub fn generate_name(link: &str, name: Option<String>) -> String {
        let mut name = name.unwrap_or_else(|| "".to_owned());

        // If name is not provided, use the domain name
        // If provided, replace ' ' with '_'
        if name.is_empty() {
            let m = get_domain_name(link);
            name = match m {
                Some(m) => link.substring(m.start(), m.end()).to_owned(),
                None => link.to_string(),
            }
        } else {
            name = name.replace(' ', "_");
        }

        name
    }

    /// Return bookmark with values
    pub fn generate_bookmark(id: u32, link: String, name: String) -> Bookmark {
        Bookmark {
            is_file: !is_url(&link),
            link,
            name,
            date: Local::now().to_string(),
            id,
        }
    }

    /// Print a coloured output
    /// id -> yellow bold
    /// name -> cyan bold
    /// link -> blue
    pub fn colored_fmt(&self) {
        println!(
            "{} {} {}",
            self.id.to_string().yellow().bold(),
            self.name.cyan().bold(),
            self.link.blue()
        );
    }
}

impl fmt::Display for Bookmark {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {}", self.id, self.name, self.link)
    }
}
