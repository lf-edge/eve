// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

func TestCreateInventory(t *testing.T) {

	_, log := agentlog.Init("someAgent")

	msg := info.ZInfoHardware{}
	err := AddInventoryInfo(log, &msg)
	if err != nil {
		panic(err)
	}

	t.Log(&msg)
}
