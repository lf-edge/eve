// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evalmgr

import (
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/zboot"
)

// ZbootSystemReset implements SystemResetInterface using zboot for production reboots
type ZbootSystemReset struct{}

// NewZbootSystemReset creates a production system reset handler
func NewZbootSystemReset() *ZbootSystemReset {
	return &ZbootSystemReset{}
}

// Reset triggers a system reboot via zboot
func (z *ZbootSystemReset) Reset(log *base.LogObject) {
	zboot.Reset(log)
}

// Compile-time check that ZbootSystemReset implements SystemResetInterface
var _ SystemResetInterface = (*ZbootSystemReset)(nil)
