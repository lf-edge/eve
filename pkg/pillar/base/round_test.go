// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"math"
	"testing"
)

func TestRoundUpToMbytes(t *testing.T) {
	const mib = 1 << 20
	for in, want := range map[uint64]uint64{
		0:              0,
		1:              1,
		mib:            1,
		mib + 1:        2,
		math.MaxUint64: math.MaxUint64/mib + 1,
	} {
		if got := RoundUpToMbytes(in); got != want {
			t.Errorf("RoundUpToMbytes(%d) = %d, want %d", in, got, want)
		}
	}
}
