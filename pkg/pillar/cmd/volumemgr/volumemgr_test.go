// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package volumemgr

import (
	"fmt"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// TestMaybeUpdateConfigItems_DeferContentDeleteValues verifies that pushing
// any non-negative value for timer.defer.content.delete does not panic
// time.NewTicker. The handler computes the ticker interval as
// (deferContentDelete / 10) seconds with uint32 integer division, so any
// value in 1..9 truncates to 0 and historically caused
// "panic: non-positive interval for NewTicker", which crashes the entire
// zedbox process and forces the watchdog to reboot the device.
func TestMaybeUpdateConfigItems_DeferContentDeleteValues(t *testing.T) {
	log = base.NewSourceLogObject(logrus.StandardLogger(), "test-volumemgr", 0)

	cases := []uint32{1, 3, 5, 9, 10, 60, 3600}
	for _, val := range cases {
		val := val
		t.Run(fmt.Sprintf("DeferContentDelete=%d", val), func(t *testing.T) {
			ctx := volumemgrContext{
				globalConfig: types.DefaultConfigItemValueMap(),
			}
			// Pre-initialize deferDelete the way Run() does at startup.
			ctx.deferDelete = time.NewTicker(time.Hour)
			ctx.deferDelete.Stop()

			newCfg := types.DefaultConfigItemValueMap()
			newCfg.SetGlobalValueInt(types.DeferContentDelete, val)

			maybeUpdateConfigItems(&ctx, newCfg)

			ctx.deferDelete.Stop()
		})
	}
}
