// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use log::trace;
use std::borrow::Borrow;

// Public diff-op output; index payloads are intended API even if not yet read.
#[allow(dead_code)]
#[derive(Debug)]
pub enum DiffOp {
    Del(usize),
    Add(usize),
    Mod(usize, usize),
    Unchanged(usize),
}

pub fn collect_diff<'a, U>(
    old_good: &'a [U],
    new: &'a [U],
    lcs: &[(usize, usize)],
) -> (Vec<usize>, Vec<usize>) {
    // Find deleted (elements in old_good not present in LCS)
    let deleted_from_old: Vec<_> = old_good
        .iter()
        .enumerate()
        .filter(|(i, _)| !lcs.iter().any(|(j, _)| i == j))
        .map(|(i, _)| i)
        .collect();

    // Find added (elements in new not present in LCS)
    let added_to_new: Vec<_> = new
        .iter()
        .enumerate()
        .filter(|(i, _)| !lcs.iter().any(|(_, j)| i == j))
        .map(|(i, _)| i)
        .collect();

    (deleted_from_old, added_to_new)
}

pub fn produce_diff_ops(
    lcs: &[(usize, usize)],
    add: &[usize],
    del: &[usize],
    mods: &[(usize, usize)],
    old_len: usize,
    new_len: usize,
) -> (Vec<DiffOp>, Vec<DiffOp>) {
    let mut old_diff = Vec::new();
    let mut new_diff = Vec::new();

    let mut mods_old = mods
        .iter()
        .map(|&(old, new)| (old, new))
        .collect::<Vec<_>>();
    mods_old.sort_by_key(|e| e.0);

    let mut mods_new = mods
        .iter()
        .map(|&(old, new)| (new, old))
        .collect::<Vec<_>>();
    mods_new.sort_by_key(|e| e.0);

    // Merge del, mods (old indices), and lcs (old indices) for old array
    let (mut d, mut m, mut l, mut t) = (0, 0, 0, 0);
    while d < del.len() || m < mods.len() || l < lcs.len() || t < old_len {
        let current_d = if d < del.len() { del[d] } else { usize::MAX };
        let current_m = if m < mods.len() {
            mods_old[m].0
        } else {
            usize::MAX
        };
        let current_l = if l < lcs.len() { lcs[l].0 } else { usize::MAX };

        let min_val = current_d.min(current_m).min(current_l);

        // print all current and min values
        trace!(
            "d: {}, m: {}, l: {}: MIN: {} [t={}]",
            current_d,
            current_m,
            current_l,
            min_val,
            t
        );
        // we add either one of the three events or if none of them, we add the unchanged event
        if min_val == current_d {
            old_diff.push(DiffOp::Del(current_d));
            d += 1;
        } else if min_val == current_m {
            let (old, new) = mods_old[m];
            old_diff.push(DiffOp::Mod(old, new));
            m += 1;
        } else if min_val == current_l {
            let (old, _new) = lcs[l];
            old_diff.push(DiffOp::Unchanged(old));
            l += 1;
        } else {
            old_diff.push(DiffOp::Unchanged(t));
        }
        t += 1;
    }

    // Merge add, mods (new indices), and lcs (new indices) for new array
    let (mut a, mut m, mut l, mut t) = (0, 0, 0, 0);
    while a < add.len() || m < mods.len() || l < lcs.len() || t < new_len {
        let current_a = if a < add.len() { add[a] } else { usize::MAX };
        let current_m = if m < mods.len() {
            mods_new[m].0
        } else {
            usize::MAX
        };
        let current_l = if l < lcs.len() { lcs[l].1 } else { usize::MAX };

        let min_val = current_a.min(current_m).min(current_l);

        // print all current and min values
        trace!(
            "a: {}, m: {}, l: {}: MIN: {} [t={}]",
            current_a,
            current_m,
            current_l,
            min_val,
            t
        );

        if min_val == current_a {
            new_diff.push(DiffOp::Add(current_a));
            a += 1;
        } else if min_val == current_m {
            let (new, old) = mods_new[m];
            new_diff.push(DiffOp::Mod(old, new));
            m += 1;
        } else if min_val == current_l {
            let (_old, new) = lcs[l];
            new_diff.push(DiffOp::Unchanged(new));
            l += 1;
        } else {
            new_diff.push(DiffOp::Unchanged(t));
        }
        t += 1;
    }

    (old_diff, new_diff)
}

pub fn compute_lcs<'a, T, U, V>(old: &'a [U], new: &'a [V]) -> Vec<(usize, usize)>
where
    T: PartialEq + ?Sized,
    U: Borrow<T>,
    V: Borrow<T>,
{
    let old_len = old.len();
    let new_len = new.len();

    // Initialize DP table with dimensions (good_len + 1) x (bad_len + 1)
    let mut dp = vec![vec![0; new_len + 1]; old_len + 1];

    // Fill the DP table
    for i in 1..=old_len {
        for j in 1..=new_len {
            if old[i - 1].borrow() == new[j - 1].borrow() {
                // Events match: extend the LCS
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                // Take the maximum of the left or top cell
                dp[i][j] = std::cmp::max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }

    // Backtrack to reconstruct the LCS
    let mut i = old_len;
    let mut j = new_len;
    let mut lcs = Vec::new();

    while i > 0 && j > 0 {
        if old[i - 1].borrow() == new[j - 1].borrow() {
            // Include the matching event in the LCS
            lcs.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] > dp[i][j - 1] {
            // Move up (prioritize the good log)
            i -= 1;
        } else {
            // Move left (prioritize the bad log)
            j -= 1;
        }
    }

    // Reverse to restore original order
    lcs.reverse();
    lcs
}

#[cfg(test)]
mod tests {

    use crate::diff::semantic::{diff_semantic, LcsSemanticKey};

    use super::*;
    use std::fmt;
    #[test]
    fn mixed_ownership() {
        // Old: Vec<String> (owned), New: &[&str] (references)
        let old = vec!["a".to_string(), "b".to_string()];
        let new = &["a", "b", "c"];
        assert_eq!(compute_lcs::<str, _, _>(&old, new), vec![(0, 0), (1, 1)]);
    }

    #[test]
    fn slice_of_references() {
        // Both slices use references
        let old = &[1, 2, 3];
        let new = &[2, 3, 4];
        assert_eq!(compute_lcs(old, new), vec![(1, 0), (2, 1)]);
    }

    #[test]
    fn mixed_types() {
        // Old: Vec<String>, New: &[&str]
        let old = vec!["apple".to_string(), "banana".to_string()];
        let new = &["apple", "orange", "banana"];
        assert_eq!(compute_lcs::<str, _, _>(&old, new), vec![(0, 0), (1, 2)]);
    }

    #[test]
    fn both_empty() {
        let old: Vec<i32> = vec![];
        let new: Vec<i32> = vec![];
        assert_eq!(compute_lcs(&old, &new), vec![]);
    }

    #[test]
    fn old_empty() {
        let old: Vec<i32> = vec![];
        let new = vec![1, 2, 3];
        assert_eq!(compute_lcs(&old, &new), vec![]);
    }

    #[test]
    fn new_empty() {
        let old = vec![1, 2, 3];
        let new: Vec<i32> = vec![];
        assert_eq!(compute_lcs(&old, &new), vec![]);
    }

    #[test]
    fn identical_sequences() {
        let old = vec![1, 2, 3];
        let new = vec![1, 2, 3];
        let expected = vec![(0, 0), (1, 1), (2, 2)];
        assert_eq!(compute_lcs(&old, &new), expected);
    }

    #[test]
    fn no_common_elements() {
        let old = vec![1, 2];
        let new = vec![3, 4];
        assert!(compute_lcs(&old, &new).is_empty());
    }

    #[test]
    fn partial_subsequence() {
        let old = vec![1, 2, 3, 4];
        let new = vec![1, 3, 4, 5];
        let expected = vec![(0, 0), (2, 1), (3, 2)];
        assert_eq!(compute_lcs(&old, &new), expected);
    }

    #[test]
    fn single_element_match() {
        let old = vec![1, 2, 3];
        let new = vec![4, 2, 5];
        assert_eq!(compute_lcs(&old, &new), vec![(1, 1)]);
    }

    #[test]
    fn strings_borrow_str() {
        let old = vec!["apple".to_string(), "banana".to_string()];
        let new = vec![
            "apple".to_string(),
            "orange".to_string(),
            "banana".to_string(),
        ];
        let expected = vec![(0, 0), (1, 2)];
        assert_eq!(compute_lcs::<str, _, _>(&old, &new), expected);
    }

    #[test]
    fn non_consecutive_elements() {
        let old = vec![1, 2, 3, 4];
        let new = vec![1, 3, 5, 4];
        let expected = vec![(0, 0), (2, 1), (3, 3)];
        assert_eq!(compute_lcs(&old, &new), expected);
    }

    #[test]
    fn single_element_sequences() {
        let old = vec![5];
        let new = vec![5];
        assert_eq!(compute_lcs(&old, &new), vec![(0, 0)]);
    }

    // Test event type implementing required traits
    #[derive(Debug, PartialEq, Clone)]
    struct TestEvent {
        event_type: String,
        data: String,
    }

    impl<'a> LcsSemanticKey<'a, String> for TestEvent {
        fn semantic_key(&'a self) -> String {
            self.event_type.clone()
        }
    }

    impl fmt::Display for TestEvent {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}: {}", self.event_type, self.data)
        }
    }

    // Helper functions
    fn boot_order(value: &str) -> TestEvent {
        TestEvent {
            event_type: "BootOrder".to_string(),
            data: value.to_string(),
        }
    }

    fn usb_event(device: &str) -> TestEvent {
        TestEvent {
            event_type: "USBDevice".to_string(),
            data: device.to_string(),
        }
    }

    fn bios_access() -> TestEvent {
        TestEvent {
            event_type: "BIOSAccess".to_string(),
            data: "Entered".to_string(),
        }
    }

    fn boot_entry(index: u16, val: &str) -> TestEvent {
        TestEvent {
            event_type: format!("BootEntry{:04X}", index),
            data: val.to_string(),
        }
    }

    #[test]
    fn lcs_basic_sequence() {
        let old = vec![boot_order("0001"), usb_event("SanDisk"), bios_access()];

        let new = vec![boot_order("0001"), usb_event("SanDisk"), bios_access()];

        let lcs = compute_lcs(&old, &new);
        assert_eq!(lcs, vec![(0, 0), (1, 1), (2, 2)]);
    }

    #[test]
    fn lcs_reordered_events() {
        let old = vec![boot_order("0001"), usb_event("SanDisk"), bios_access()];

        let new = vec![usb_event("SanDisk"), boot_order("0001"), bios_access()];

        let lcs = compute_lcs(&old, &new);

        assert_eq!(lcs.len(), 2);
    }

    #[test]
    fn collect_diff_add_remove() {
        let old = vec![boot_order("0001"), bios_access()];
        let new = vec![boot_order("0001"), usb_event("SanDisk")];

        let lcs = compute_lcs(&old, &new);
        let (deleted, added) = collect_diff(&old, &new, &lcs);

        assert_eq!(deleted, vec![1]); // bios_access removed
        assert_eq!(added, vec![1]); // usb_event added
    }

    #[test]
    fn semantic_modification_detection() {
        let old = vec![boot_order("0001"), usb_event("SanDisk")];

        let new = vec![
            boot_order("0002"), // Modified BootOrder
            usb_event("SanDisk"),
            bios_access(), // New event
        ];

        let lcs = compute_lcs(&old, &new);
        let (del, ins) = collect_diff(&old, &new, &lcs);
        let (del_final, new_final, mods) = diff_semantic(&old, &new, &del, &ins);

        // BootOrder (index 0) modified
        assert_eq!(mods, vec![(0, 0)]);
        // bios_access added
        assert_eq!(new_final, vec![2]);
        // Original USB event remains unchanged
        assert!(del_final.is_empty());
    }

    #[test]
    fn complex_scenario() {
        // Initial state
        let old = vec![boot_order("0001"), usb_event("SanDisk"), bios_access()];

        // After changes: BootOrder modified, USB removed, BIOS accessed twice
        let new = vec![
            boot_order("0002"),
            bios_access(),
            bios_access(),
            bios_access(),
        ];

        let lcs = compute_lcs(&old, &new);
        let (del, ins) = collect_diff(&old, &new, &lcs);
        let (del_final, new_final, mods) = diff_semantic(&old, &new, &del, &ins);

        // Modified BootOrder
        assert_eq!(mods, vec![(0, 0)]);
        // Removed USB device
        assert_eq!(del_final, vec![1]);
        // Added BIOS accesses (treated as new events since semantic key is same but data matches)
        assert_eq!(new_final, vec![1, 2]);
    }

    #[test]
    fn identical_logs() {
        let log = vec![boot_order("0001"), usb_event("Kingston")];

        let lcs = compute_lcs(&log, &log);
        let (del, ins) = collect_diff(&log, &log, &lcs);
        let (del_final, new_final, mods) = diff_semantic(&log, &log, &del, &ins);

        assert!(del_final.is_empty());
        assert!(new_final.is_empty());
        assert!(mods.is_empty());
    }

    #[test]
    fn modified_and_added_same_type() {
        let old = vec![
            boot_order("0001"),
            boot_entry(0, "0001"),
            boot_entry(2, "0001"), // Deleted
        ];

        let new = vec![
            boot_order("0002"), // Modified
            boot_entry(0, "0001"),
            boot_entry(1, "0001"), // Added
        ];

        let lcs = compute_lcs(&old, &new);
        let (del, ins) = collect_diff(&old, &new, &lcs);
        let (del_final, new_final, mods) = diff_semantic(&old, &new, &del, &ins);

        // One modification (0001 → 0002)
        assert_eq!(mods, vec![(0, 0)]);
        // One new BootOrder (Boot0001: "0001")
        assert_eq!(new_final, vec![2]);
        // One deleted BootOrder (original duplicate)
        assert_eq!(del_final, vec![2]);
    }
}
