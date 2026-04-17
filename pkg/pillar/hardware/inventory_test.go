// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hardware

import (
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/agentlog"
)

func TestCreateInventory(t *testing.T) {

	_, log := agentlog.Init("someAgent")

	inventory, err := GetInventoryInfo(log)
	// often the tests do not run as root, do not fail in this case
	if inventory == nil || (err != nil && !errors.Is(err, os.ErrPermission)) {
		t.Fatalf("creating inventory failed: %v", err)
	}

	bytes, err := json.MarshalIndent(inventory, "\t", "\t")
	if err != nil {
		t.Fatalf("could not create json: %v", err)
	}
	t.Log(string(bytes))
}
