// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ExecConfig.Key / ExecStatus.Key

func TestExecConfigKey(t *testing.T) {
	cfg := ExecConfig{Caller: "zedagent"}
	assert.Equal(t, "zedagent", cfg.Key())
}

func TestExecStatusKey(t *testing.T) {
	status := ExecStatus{Caller: "baseosmgr"}
	assert.Equal(t, "baseosmgr", status.Key())
}
