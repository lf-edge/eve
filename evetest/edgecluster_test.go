// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"reflect"
	"testing"

	eveinfo "github.com/lf-edge/eve-api/go/info"
)

// appNodeNames reports every node that hosts the app, so a VMI being
// replaced shows up next to its successor, while finished VMIs and other
// apps are left out.
func TestAppNodeNames(t *testing.T) {
	info := &eveinfo.ZInfoKubeCluster{
		EveVmApps: []*eveinfo.KubeVMIInfo{
			{Name: "vm2-349cc-1gbx8p", NodeName: "edge-dev1",
				Status: eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_RUNNING},
			{Name: "vm2-349cc-2abcde", NodeName: "edge-dev3",
				Status: eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_SCHEDULED},
			{Name: "vm2-349cc-0old00", NodeName: "edge-dev2",
				Status: eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_SUCCEEDED},
			{Name: "vm2-349cc-0old01", NodeName: "edge-dev2",
				Status: eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_FAILED},
			{Name: "vm2-349cc-pending", NodeName: "",
				Status: eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_PENDING},
			{Name: "vm20-aaaaa-0", NodeName: "edge-dev2",
				Status: eveinfo.KubeVMIStatus_KUBE_VMI_STATUS_RUNNING},
		},
	}
	got := appNodeNames(info, "vm2")
	want := []string{"edge-dev1", "edge-dev3"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("appNodeNames = %v, want %v", got, want)
	}
	if got := appNodeNames(info, "vm9"); got != nil {
		t.Fatalf("appNodeNames for an unknown app = %v, want nil", got)
	}
}
