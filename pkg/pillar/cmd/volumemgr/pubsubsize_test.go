// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"errors"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/stretchr/testify/assert"
)

func TestCutErrorIfOversizedLeavesAFittingStatusAlone(t *testing.T) {
	errStr := strings.Repeat("x", 1000)
	cut := cutErrorIfOversized("key", func() error { return nil }, &errStr)
	assert.False(t, cut)
	assert.Equal(t, strings.Repeat("x", 1000), errStr)
}

func TestCutErrorIfOversizedCutsTheErrorOfAnOversizedStatus(t *testing.T) {
	errStr := strings.Repeat("x", 1000)
	cut := cutErrorIfOversized("key",
		func() error { return errors.New("too large") }, &errStr)
	assert.True(t, cut)
	assert.LessOrEqual(t, len(errStr), types.OversizedStatusErrorLen)
	assert.Contains(t, errStr, "bytes dropped")
}

func TestCutErrorIfOversizedSkipsTheCheckWithoutAnError(t *testing.T) {
	errStr := ""
	checked := false
	cut := cutErrorIfOversized("key", func() error {
		checked = true
		return errors.New("too large")
	}, &errStr)
	assert.False(t, cut)
	assert.False(t, checked)
}
