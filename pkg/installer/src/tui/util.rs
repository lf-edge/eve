/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

use ratatui::layout::Rect;

/// Wizard step indicator, e.g. (1, 4, "Filesystem") -> "Step 2/4 · Filesystem".
/// `index` is 0-based; `total` is the number of screens.
pub fn step_title(index: usize, total: usize, title: &str) -> String {
    format!("Step {}/{} · {}", index + 1, total, title)
}

/// A dialog rectangle centered in `area`, sized up to `max_w` × `max_h` but
/// always leaving a margin so the backdrop shows around it as a popup.
pub fn centered_rect(area: Rect, max_w: u16, max_h: u16) -> Rect {
    let w = max_w.min(area.width.saturating_sub(6)).max(1);
    let h = max_h.min(area.height.saturating_sub(4)).max(1);
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect { x, y, width: w, height: h }
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

    #[test]
    fn centered_rect_is_centered_and_margined() {
        let full = Rect { x: 0, y: 0, width: 80, height: 24 };
        let r = centered_rect(full, 76, 22);
        // capped by the margin (width-6, height-4), then centered
        assert_eq!(r.width, 74);
        assert_eq!(r.height, 20);
        assert_eq!(r.x, 3);
        assert_eq!(r.y, 2);
    }

    #[test]
    fn centered_rect_shrinks_on_tiny_area() {
        let tiny = Rect { x: 0, y: 0, width: 10, height: 6 };
        let r = centered_rect(tiny, 76, 22);
        assert_eq!(r.width, 4); // 10 - 6
        assert_eq!(r.height, 2); // 6 - 4
    }
}
