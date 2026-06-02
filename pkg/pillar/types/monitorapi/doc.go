// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// The generator reads this package and emits both the Go union codec
// (union_json.gen.go, required for this package to compile) and the Rust
// contract types (into the colocated TUI crate at pkg/monitor/src/ipc).
// Run `go generate ./types/monitorapi/...` before committing; CI verifies the
// committed output matches.
//
//go:generate go run ./internal/gen -src . -rust ../../../monitor/src/ipc/monitorapi.gen.rs
//go:generate go test . -run ^TestFixtures$ -update
