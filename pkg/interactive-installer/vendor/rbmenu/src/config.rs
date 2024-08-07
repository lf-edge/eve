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

use structopt::StructOpt;

use crate::bookmark_query::{BookmarkQuery, BookmarkUpdateQuery};

#[derive(StructOpt, Debug)]
pub struct Config {
    #[structopt(subcommand)]
    pub sub_cmd: SubOpt,

    ///Add verbosity to output
    #[structopt(long)]
    pub verbose: bool,
}

#[derive(Debug, StructOpt)]
pub enum SubOpt {
    Insert {
        #[structopt(long, short)]
        name: Option<String>,
        #[structopt(long, short)]
        url: String,
    },
    #[structopt(alias = "rm")]
    Remove {
        #[structopt(flatten)]
        query: BookmarkQuery,
    },
    #[structopt(alias = "ls")]
    List {
        /// Show only the link of the bookmark
        #[structopt(global = true, short = "l", long = "show-link")]
        show_link: bool,

        #[structopt(flatten)]
        query: BookmarkQuery,
    },
    Update {
        #[structopt(flatten)]
        query: BookmarkUpdateQuery,
    },
}
