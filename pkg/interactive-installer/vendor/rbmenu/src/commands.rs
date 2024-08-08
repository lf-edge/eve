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

use crate::{
    bookmark::Bookmark,
    bookmark_query::{BookmarkQuery, BookmarkUpdateQuery},
    data::Data,
    error::Result,
};

/// Insert commands
/// Adds the bookmark to the data list and increments the last id
pub fn insert(url: String, mut data: Data, name: Option<String>) -> Result<()> {
    let name = Bookmark::generate_name(&url, name);

    let bookmark = Bookmark::generate_bookmark(data.last_id + 1, url, name);
    data.add_new_bookmark(bookmark);

    data.write_to_file()
}

/// List command
/// List all the bookmarks if no name flag was provided
/// List bookmarks that match the regex provided in name flag
pub fn list(data: &Data, query: BookmarkQuery) -> Result<Vec<&Bookmark>> {
    let id = query.id;
    let name = query.name;

    if let Some(id) = id {
        if let Some(b) = data.get_bookmark(id) {
            return Ok(vec![b]);
        }

        return Ok(vec![]);
    }
    let name = name.unwrap_or_else(|| "".to_owned());
    data.filter_bookmark(name)
}

/// Remove command
/// Exits if bookmark with the said id is not available
/// Remove the bookmark with the given id and exit.
pub fn remove(data: &mut Data, query: BookmarkQuery) -> Result<Vec<Bookmark>> {
    let id = query.id;
    let name = query.name;

    let mut removed = vec![];

    if let Some(name) = name {
        let i = data.remove_with_regex_name(name)?;
        for a in i {
            removed.push(a);
        }
    };
    if let Some(id) = id {
        if let Some(b) = data.remove_with_id(id) {
            removed.push(b)
        }
    };

    data.write_to_file()?;
    Ok(removed)
}

pub fn update(data: &mut Data, query: BookmarkUpdateQuery) -> Result<()> {
    data.bookmarks
        .iter_mut()
        .map(|e| {
            if e.id != query.id {
                return;
            }

            let name = query.name.as_ref().unwrap_or(&e.name);
            let link = query.link.as_ref().unwrap_or(&e.link);

            e.name = name.to_string().replace(' ', "_");
            e.link = link.to_string();
        })
        .for_each(drop);

    data.write_to_file()
}
