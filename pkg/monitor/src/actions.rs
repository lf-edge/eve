// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::ui::ipdialog::InterfaceState;

#[derive(Debug, Clone, PartialEq)]
pub enum MonActions {
    NetworkInterfaceUpdated(InterfaceState, InterfaceState),
    ServerUpdated(String),
}
