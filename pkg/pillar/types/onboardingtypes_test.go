// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// OnboardingStatus.Key / LogKey

func TestOnboardingStatusLogKey(t *testing.T) {
	s := OnboardingStatus{}
	assert.Equal(t, "global", s.Key())
	assert.Contains(t, s.LogKey(), "global")
}
