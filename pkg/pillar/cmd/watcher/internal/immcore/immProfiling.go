// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build immprofiling

package immcore

import (
	"time"
)

// enableIMMProfilingAtStartup turns on low-overhead IMM profiling with defaults.
func enableIMMProfilingAtStartup() {
	SetProfiling(true)
	SetProfilingConfig(1*time.Millisecond, 1)
}

func init() {
	enableIMMProfilingAtStartup()
}
