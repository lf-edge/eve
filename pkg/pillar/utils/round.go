// Copyright (c) 2018-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

// RoundToMbytes - Byts convert to Mbytes with round-off
func RoundToMbytes(byteCount uint64) uint64 {
	const mbyte = 1 << 20

	return (byteCount + mbyte/2) / mbyte
}
