// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use log::trace;
use std::collections::HashMap;

pub trait LcsSemanticKey<'a, S>
where
    S: Eq,
{
    fn semantic_key(&'a self) -> S;
}

// Detect simanctic Modifications
// if the same event exists in both deltions and insetions then it is a modification
// e.g. BootOrder changed from [1, 2, 3] to [1, 3, 2]. It is marked as deleted in
// good log and inserted in bad log. However this is the same event with different data.
pub fn diff_semantic<'a, T, S>(
    old: &'a [T],
    new: &'a [T],
    deleted_events: &[usize],
    added_events: &[usize],
) -> (Vec<usize>, Vec<usize>, Vec<(usize, usize)>)
where
    T: LcsSemanticKey<'a, S> + PartialEq + std::fmt::Display,
    S: Eq + std::hash::Hash + std::fmt::Display,
{
    let mut mods = Vec::new();
    let mut new_events = Vec::new();

    let mut del_map = deleted_events
        .iter()
        .map(|e| {
            let key = old[*e].semantic_key();
            (key, *e)
        })
        .collect::<HashMap<S, usize>>();

    for new_event in added_events.iter() {
        trace!("key: {}", new[*new_event].semantic_key());
        if let Some(old_event) = del_map.remove(&new[*new_event].semantic_key()) {
            // LCS is not good when events were reordered
            // only add to mods if events are different
            if old[old_event] != new[*new_event] {
                mods.push((old_event, *new_event));
            }
        } else {
            new_events.push(*new_event);
        }
    }

    // what is left in hashmap are real deleted events
    // FIXME: do we care about the order?
    let deleted_events = del_map.into_values().collect::<Vec<_>>();

    (deleted_events, new_events, mods)
}
