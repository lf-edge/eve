// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"testing"
)

func TestGetDomsCPUMem(t *testing.T) {
	ctx, err := initContainerd()
	if err != nil {
		t.Skipf("test must be run on a system with a functional containerd")
	}

	res, err := ctx.GetDomsCPUMem()
	if err != nil {
		t.Errorf("can't get domain statistics %v", err)
	}

	for k, v := range res {
		if v.UsedMemoryPercent < 0 || v.UsedMemoryPercent > 100 || v.CPUTotalNs != 0 || v.AvailableMemory < v.UsedMemory {
			t.Errorf("result from get domain statistics doesn't make sense %s: %+v", k, v)
		}
	}
}
