/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::config::InstallConfig;
use crate::disk::Disk;
use crate::plan::HardwareFacts;

pub struct WizardState {
    pub disks: Vec<Disk>,
    pub boot: Option<String>,
    pub config: InstallConfig,
    /// Hardware facts for the Overview plan preview (gathered once by the caller).
    pub hw: HardwareFacts,
}

pub enum Outcome {
    Completed(InstallConfig),
    Cancelled,
}
