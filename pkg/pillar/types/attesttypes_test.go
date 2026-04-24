// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// AttestState.String — all named states and the default

func TestAttestStateString(t *testing.T) {
	cases := []struct {
		state AttestState
		want  string
	}{
		{StateNone, "StateNone"},
		{StateNonceWait, "StateNonceWait"},
		{StateInternalQuoteWait, "StateInternalQuoteWait"},
		{StateInternalEscrowWait, "StateInternalEscrowWait"},
		{StateAttestWait, "StateAttestWait"},
		{StateAttestEscrowWait, "StateAttestEscrowWait"},
		{StateRestartWait, "StateRestartWait"},
		{StateComplete, "StateComplete"},
		{StateAny, "StateAny"},
		{AttestState(99), "Unknown State"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.state.String(), "state=%d", tc.state)
	}
}
