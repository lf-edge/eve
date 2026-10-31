// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"math"
)

// RoundToMbytes - Bytes converted to Mbytes with round-off
func RoundToMbytes(byteCount uint64) uint64 {
	const mbyte = 1 << 20

	return (byteCount + mbyte/2) / mbyte
}

// RoundUpToMbytes - Bytes converted to Mbytes with round-up; cannot overflow,
// even for math.MaxUint64 (cgroup.Unlimited)
func RoundUpToMbytes(byteCount uint64) uint64 {
	const mbyte = 1 << 20

	mb := byteCount / mbyte
	if byteCount%mbyte != 0 {
		mb++
	}
	return mb
}

// ClampToUint32 - ensure it doesn't exceed MaxUint32
func ClampToUint32(val uint64) uint32 {
	if val > math.MaxUint32 {
		return math.MaxUint32
	} else {
		return uint32(val)
	}
}
