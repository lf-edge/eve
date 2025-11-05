// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"testing"

	"github.com/lf-edge/eve-api/go/info"
)

func TestCreateInventory(t *testing.T) {

	msg := info.ZInfoHardware{}
	err := AddInventoryInfo(&msg)
	if err != nil {
		panic(err)
	}

	t.Log(&msg)
}
