// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod device;
// `model::model` is an established path; keep the name rather than churn callers.
#[allow(clippy::module_inception)]
pub mod model;
