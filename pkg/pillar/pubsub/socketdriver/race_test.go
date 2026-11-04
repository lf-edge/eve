// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package socketdriver

// raceEnabled reports whether the race detector is on: the compiler then
// allocates differently, see TestAllocCountsReceive.
const raceEnabled = true
