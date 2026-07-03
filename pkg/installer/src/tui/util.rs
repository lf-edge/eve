/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

/// Wizard step indicator, e.g. (1, 4, "Filesystem") -> "Step 2/4 · Filesystem".
/// `index` is 0-based; `total` is the number of screens.
pub fn step_title(index: usize, total: usize, title: &str) -> String {
    format!("Step {}/{} · {}", index + 1, total, title)
}

/// Human-readable size, e.g. 42949672960 -> "40.0G".
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{}{}", bytes, UNITS[0])
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizes() {
        assert_eq!(human_size(512), "512B");
        assert_eq!(human_size(40 * 1024 * 1024 * 1024), "40.0G");
        assert_eq!(human_size(1536 * 1024 * 1024), "1.5G");
    }

    #[test]
    fn step_titles() {
        assert_eq!(step_title(0, 4, "Select install disk"), "Step 1/4 · Select install disk");
        assert_eq!(step_title(3, 4, "Overview"), "Step 4/4 · Overview");
    }
}
