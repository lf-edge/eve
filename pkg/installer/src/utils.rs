/*
 * Copyright (c) 2024 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::{fs};
use cursive::Cursive;
use serde_json::Value;
use anyhow::{Context, Result};

use crate::{
    actions::execute,
    error::Error,
    state::{GlobalState, Move},
};

pub fn read_installer_json(json_file: &str) -> Result<Value> {
    let text = fs::read_to_string(json_file)
        .with_context(|| format!("Failed to read file: {}", json_file))?;
    let json_value = serde_json::from_str::<Value>(&text)
        .with_context(|| format!("Failed to parse JSON from file: {}", json_file))?;
    Ok(json_value)

}

pub fn get_state_mut(c: &mut Cursive) -> Result<GlobalState, Error> {
    match c.take_user_data::<GlobalState>() {
        Some(data) => {
            c.set_user_data(data.clone());
            Ok(data)
        }
        None => Err(Error::NoState),
    }
}

pub fn get_block_devices() -> Option<Vec<String>> {
    let mut vec = Vec::new();
    let block_devices_path = "/sys/class/block";
    let block_devices = fs::read_dir(block_devices_path).ok()?;

    for block_device in block_devices {
        match block_device {
            Ok(block_device) => {
                let path = block_device.path();
                if path.is_dir() {
                    let name = path.file_name()?.to_string_lossy().to_string();

                    // Exclude loop devices
                    if !name.starts_with("loop") && !name.starts_with("ram") {
                        vec.push(name);
                    }
                }
            }
            Err(_) => {
                // Ignore errors when reading directory entries
                continue;
            }
        }
    }

    // Sort the device names alphabetically
    vec.sort();

    if vec.is_empty() {
        None
    } else {
        Some(vec)
    }
}

pub fn press_next(c: &mut Cursive) {
    let cb = c.cb_sink().clone();
    cb.send(Box::new(move |s: &mut cursive::Cursive| {
        let _ = execute(s, Move::Next);
    }))
    .unwrap();
}

pub fn save_config_value(c: &mut Cursive, k: &str, v: &str, m: bool) -> crate::error::Result<()> {
    let mut s: GlobalState = c.take_user_data().unwrap();
    s.data.map.insert(k.to_string(), v.to_string());
    c.set_user_data(s);

    if m {
        press_next(c);
    }

    Ok(())
}

pub fn add_config_value(c: &mut Cursive, k: &str, v: &str) -> crate::error::Result<()> {
    let mut s: GlobalState = c.take_user_data().unwrap();
    let mut vadd = s.data.map.get(k).cloned().unwrap_or_default();
    if vadd == "_____" {
        vadd = v.to_string();
    } else {
        vadd = vadd + "," + v;
    }
    s.data.map.insert(k.to_string(), vadd);
    c.set_user_data(s);
    Ok(())
}

pub fn remove_config_value(c: &mut Cursive, k: &str, v: &str) -> crate::error::Result<()> {
    let mut s: GlobalState = c.take_user_data().unwrap();
    let mut vremove: String = s.data.map.get(k).cloned().unwrap_or_default()
        .split(',')
        .filter(|&d| d != v) // Remove matching device
        .collect::<Vec<&str>>() // Collect filtered items into Vec
        .join(","); // Join them back with ','

    if vremove == "" { // If we removed all devices we return to the init value
        vremove = "_____".to_string()
    }

    s.data.map.insert(k.to_string(), vremove);
    c.set_user_data(s);
    Ok(())
}

#[macro_export]
macro_rules! herr {
    ($c:expr,$f:expr) => {{
        if let Err(e) = $f($c) {
            e.show_dialog($c);
            return
        }
    }};
    ($c:expr,$f:expr,$($args:expr),*) => {{
        if let Err(e) = $f($c,$($args),*) {
            e.show_dialog($c);
            return
        }
    }};
}

#[macro_export]
macro_rules! herrcl {
    ($f:expr) => {{
        |c| {
            use crate::herr;
            herr!(c,$f);
        }
    }};
    ($f:expr,$($args:expr),*) => {{
        move |c| {
            use crate::herr;
            herr!(c,$f,$($args),*);
        }
    }};
}
