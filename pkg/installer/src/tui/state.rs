/*
 * Copyright (c) 2026 Zededa, Inc.
 * SPDX-License-Identifier: Apache-2.0
 */
use crate::config::InstallConfig;
use crate::disk::Disk;

pub struct WizardState {
    pub disks: Vec<Disk>,
    pub boot: Option<String>,
    pub config: InstallConfig,
}

pub enum Outcome {
    Completed(InstallConfig),
    Cancelled,
}
