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

// AttestNonce / AttestQuote / EdgeNodeCert Key / LogKey

func TestAttestNonceLogKey(t *testing.T) {
	n := AttestNonce{Nonce: []byte{0xab, 0xcd}}
	assert.NotEmpty(t, n.Key())
	assert.Contains(t, n.LogKey(), n.Key())
}

func TestAttestQuoteLogKey(t *testing.T) {
	q := AttestQuote{Nonce: []byte{0x01, 0x02, 0x03}}
	assert.NotEmpty(t, q.Key())
	assert.Contains(t, q.LogKey(), q.Key())
}

func TestEdgeNodeCertLogKey(t *testing.T) {
	cert := EdgeNodeCert{CertID: []byte{0xff, 0xee}}
	assert.NotEmpty(t, cert.Key())
	assert.Contains(t, cert.LogKey(), cert.Key())
}
