// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/stretchr/testify/assert"
)

// VaultStatus.IsVaultInError

func TestVaultStatusIsVaultInError(t *testing.T) {
	// No error status → false
	s := VaultStatus{Status: info.DataSecAtRestStatus_DATASEC_AT_REST_ENABLED}
	assert.False(t, s.IsVaultInError())

	// Error status but no mismatching PCRs → false
	s.Status = info.DataSecAtRestStatus_DATASEC_AT_REST_ERROR
	assert.False(t, s.IsVaultInError())

	// Error status with mismatching PCRs → true
	s.MismatchingPCRs = []int{0, 1, 7}
	assert.True(t, s.IsVaultInError())
}
