// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ServiceInitStatus.Key / LogKey

func TestServiceInitStatusLogKey(t *testing.T) {
	s := ServiceInitStatus{ServiceName: "zedagent"}
	assert.Equal(t, "zedagent", s.Key())
	assert.Contains(t, s.LogKey(), "zedagent")
}
