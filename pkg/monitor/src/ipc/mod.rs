// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod ipc_client;
pub mod message;

// Generated contract types — source of truth is the Go package
// pkg/pillar/types/monitorapi. Regenerate via `go generate` there.
#[path = "monitorapi.gen.rs"]
pub mod monitorapi;

// Hand-written helpers on the generated contract types.
mod tpm;

#[cfg(test)]
mod monitorapi_tests;
