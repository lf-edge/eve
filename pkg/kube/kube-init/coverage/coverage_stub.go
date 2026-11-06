// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !cover

// Package coverage is a no-op unless built with -tags cover.
package coverage

// Flush is a no-op in non-coverage builds.
func Flush() {}
