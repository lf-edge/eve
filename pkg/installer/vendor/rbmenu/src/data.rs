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

use home::home_dir;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

use crate::{
    bookmark::Bookmark,
    error::{Error, Result},
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Data {
    pub bookmarks: Vec<Bookmark>,
    pub last_id: u32,
}

impl Data {
    /// Prettify the json and write to file
    pub fn write_to_file(&self) -> Result<()> {
        let path = get_data_file_path()?;

        let pretty = match serde_json::to_string_pretty(&self) {
            Ok(e) => e,
            Err(_) => return Err(Error::JsonPrettify),
        };

        if fs::write(path, pretty).is_err() {
            Err(Error::DataFileWrite)
        } else {
            Ok(())
        }
    }

    pub fn add_new_bookmark(&mut self, bookmark: Bookmark) {
        self.bookmarks.push(bookmark);
        self.last_id += 1;
    }

    // TODO refactor to a hashmap prolly
    pub fn get_bookmark(&self, id: u32) -> Option<&Bookmark> {
        let mut bookmark = None;
        for b in &self.bookmarks {
            if b.id == id {
                bookmark = Some(b);
                break;
            }
        }
        bookmark
    }

    pub fn filter_bookmark(&self, name: String) -> Result<Vec<&Bookmark>> {
        let r = Regex::new(&name)?;

        Ok(self
            .bookmarks
            .iter()
            .filter(|b| r.is_match(&b.name))
            .collect::<Vec<&Bookmark>>())
    }

    pub fn remove_with_regex_name(&mut self, name: String) -> Result<Vec<Bookmark>> {
        let r = Regex::new(&name)?;

        Ok(self
            .bookmarks
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(_i, b)| r.is_match(&b.name))
            .map(|(i, b)| {
                self.bookmarks.remove(i);
                b
            })
            .collect::<Vec<Bookmark>>())
    }

    pub fn remove_with_id(&mut self, id: u32) -> Option<Bookmark> {
        let things_to_remove = &self
            .bookmarks
            .clone()
            .into_iter()
            .enumerate()
            .filter(|(_i, b)| b.id == id)
            .map(|(i, b)| {
                self.bookmarks.remove(i);
                b
            })
            .collect::<Vec<Bookmark>>();

        if things_to_remove.is_empty() {
            None
        } else {
            Some(things_to_remove[0].clone())
        }
    }
}

pub fn get_home_dir() -> Result<PathBuf> {
    match home_dir() {
        None => Err(Error::Home),
        Some(h) => Ok(h),
    }
}

/// Create data directory and data file.data
/// Write a barebones JSON to the data file
pub fn create_data_file() -> Result<()> {
    let home = get_home_dir()?;
    let data_dir = home.join(".local/share/rbmenu/");
    let data_file = data_dir.join("bookmark.json");

    if !data_dir.exists() && fs::create_dir_all(&data_dir).is_err() {
        return Err(Error::DataDirCreate);
    }

    if !data_file.exists() && fs::File::create(&data_file).is_err() {
        return Err(Error::DataFileCreate);
    }

    let data = Data {
        bookmarks: vec![],
        last_id: 0,
    };

    data.write_to_file()
}

/// Read and parse data file into Data struct
pub fn read_data_file() -> Result<Data> {
    let data_file = get_data_file_path()?;

    if !data_file.exists() {
        create_data_file()?;
    }

    let content = match fs::read_to_string(data_file) {
        Ok(c) => c,
        Err(_) => return Err(Error::DataFileRead),
    };

    match serde_json::from_str(&content) {
        Ok(e) => Ok(e),
        Err(_) => Err(Error::DataFileParse),
    }
}

/// Return data file path
pub fn get_data_file_path() -> Result<PathBuf> {
    Ok(get_home_dir()?.join(".local/share/rbmenu/bookmark.json"))
}
