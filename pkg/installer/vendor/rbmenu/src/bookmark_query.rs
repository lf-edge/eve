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

use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Serialize, Deserialize, Debug, Clone, StructOpt)]
pub struct BookmarkQuery {
    #[structopt(long, short)]
    pub id: Option<u32>,
    #[structopt(long, short)]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, StructOpt)]
pub struct BookmarkUpdateQuery {
    #[structopt(long, short)]
    pub id: u32,
    #[structopt(long, short)]
    pub name: Option<String>,
    #[structopt(long, short)]
    pub link: Option<String>,
}
