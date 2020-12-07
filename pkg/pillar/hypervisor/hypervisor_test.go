// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"reflect"
	"testing"
)

var testDom = &types.DomainStatus{VirtualizationMode: types.HVM}
var hyper Hypervisor

func TestGetHypervisor(t *testing.T) {
	if _, err := GetHypervisor("quantum computing"); err == nil {
		t.Errorf("Expected GetHypervisor to fail for quantum computing hypervisor (it doesn't have enough qbits yes)")
	}

	if hyper, err := GetHypervisor("null"); err != nil || hyper.Name() != "null" {
		t.Errorf("Requested null hypervisor got %s (with error %v) instead", hyper.Name(), err)
	}
}

func TestGetAvailableHypervisors(t *testing.T) {
	all, enabled := GetAvailableHypervisors()
	expected := []string{"xen", "kvmtool", "kvm", "acrn", "containerd", "null"}

	if !reflect.DeepEqual(all, expected) {
		t.Errorf("wrong list of available hypervisors: %+q vs. %+q", all, expected)
	}

	if len(enabled) < 0 {
		t.Errorf("Not a single enabled hypervisor")
	}

	for _, v := range enabled {
		if v == "null" {
			return
		}
	}
	t.Errorf("null is not in the list of enabled hypervisors")
}
