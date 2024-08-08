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

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    // Unable to write to data file
    DataFileWrite,
    // Unable to prettify json
    JsonPrettify,
    // Bad Regex input
    InvalidRegex,
    // Unable to get home dir
    Home,
    // Unable to create data dir
    DataDirCreate,
    // Unable to create data file
    DataFileCreate,
    // Unable to read data file
    DataFileRead,
    // Unable to parse data file
    DataFileParse,
}

impl From<regex::Error> for Error {
    fn from(_: regex::Error) -> Self {
        Error::InvalidRegex
    }
}
