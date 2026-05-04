// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TpmSanityStatus.Key

func TestTpmSanityStatusKey(t *testing.T) {
	s := TpmSanityStatus{Name: "tpm-check"}
	assert.Equal(t, "tpm-check", s.Key())
}
