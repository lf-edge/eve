// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

func TestCreateInventory(t *testing.T) {

	_, log := agentlog.Init("someAgent")

	inventory, err := GetInventoryInfo(log)
	if err != nil {
		panic(err)
	}

	t.Log(inventory)
}
