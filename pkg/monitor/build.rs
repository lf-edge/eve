// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

fn main() {
    // if .git doesn't exist then we are not in a git repo
    // it may happen in container builds. do not set GIT_VERSION
    if !std::path::Path::new(".git").exists() {
        return;
    }

    // Get exact tag if it exists
    let exact_tag = Command::new("git")
        .args(["describe", "--tags", "--exact-match"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());

    // or get dirty description if it exists
    let dirty_descr = Command::new("git")
        .args(["describe", "--tags", "--dirty"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());

    // if git tool is not available e.g. not installed in the container
    // or the repository is not tagged, do nothing
    if let Some(version) = exact_tag.or(dirty_descr) { println!("cargo:rustc-env=GIT_VERSION={}", version) }
}
