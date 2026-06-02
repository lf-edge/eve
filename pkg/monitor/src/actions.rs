// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ui::ipdialog::InterfaceState;

// Variants carry full interface state by value by design; do not box them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum MonActions {
    NetworkInterfaceUpdated(InterfaceState, InterfaceState),
    ServerUpdated(String),
}
