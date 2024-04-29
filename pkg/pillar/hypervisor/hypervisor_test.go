// Copyright (c) 2017-2020 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
	"reflect"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

var testDom = &types.DomainStatus{VmConfig: types.VmConfig{VirtualizationMode: types.HVM}}
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
	expected := []string{"xen", "kvm", "kubevirt", "acrn", "containerd", "null"}

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

func TestBootTimeHypervisorWithHVFilePath(t *testing.T) {
	t.Skipf("enable this test once calling containerd in the test environment does not panic anymore")
	f, err := os.CreateTemp("", "eve-hv-type")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	defer os.Remove(f.Name())

	hv := bootTimeHypervisorWithHVFilePath(f.Name())

	if hv != nil {
		t.Fatal("no hypervisor should have been determined")
	}

	f.WriteString("kvm")
	hv = bootTimeHypervisorWithHVFilePath(f.Name())
	_, ok := hv.(KvmContext)
	if !ok {
		t.Fatal("hypervisor should be kvm")
	}

	f.Seek(0, 0)
	f.WriteString("xen")
	hv = bootTimeHypervisorWithHVFilePath(f.Name())
	_, ok = hv.(KvmContext)
	if !ok {
		t.Fatal("hypervisor should be xen")
	}

}
