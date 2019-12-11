// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

type LedBlinkCounter struct {
	BlinkCounter int
}

// Merge the 1/2 values based on having usable addresses or not, with
// the value we get based on access to zedcloud or errors.
func DeriveLedCounter(ledCounter, usableAddressCount int) int {
	if usableAddressCount == 0 {
		return 1
	} else if ledCounter < 2 {
		return 2
	} else {
		return ledCounter
	}
}
