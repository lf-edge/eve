// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"os"
	"testing"
)

func TestLonghornGetMajorMinorMaps(t *testing.T) {
	if _, err := os.Stat(longhornDevPath); err != nil {
		t.Skipf("No local longhorn")
	}

	mmMap, lhVolMap, err := LonghornGetMajorMinorMaps()
	if err != nil {
		t.Fatalf("LonghornGetMajorMinorMaps returned err %v", err)
	}
	for mm, lhVol := range mmMap {
		if mm == "" || lhVol == "" {
			t.Fatalf("empty major minor string (%s) or lhVol string (%s)", mm, lhVol)
		}
		if _, ok := lhVolMap[lhVol]; !ok {
			t.Fatalf("lhVol (%s) not in reverse lookup table", lhVol)
		}
	}
}

func TestSCSIGetMajMinMaps(t *testing.T) {
	mmToName, nameToMM, err := SCSIGetMajMinMaps()
	if err != nil {
		t.Fatalf("SCSIGetMajMinMaps returned %v", err)
	}
	for devName, devMajMin := range nameToMM {
		if devName == "" || devMajMin == "" {
			t.Fatalf("empty dev name (%s) or major:minor string (%s)", devName, devMajMin)
		}
		if _, ok := mmToName[devMajMin]; !ok {
			t.Fatalf("Device with major:minor string (%s) not in reverse lookup table", devMajMin)
		}
	}
}

func TestPvPvcMaps(t *testing.T) {
	_, err := GetClientSet()
	if err != nil {
		t.Skipf("No local kube or longhorn")
	}

	pvsMap, pvcsMap, err := PvPvcMaps()
	if err != nil {
		t.Fatalf("PvPvcMaps returned err %v", err)
	}
	for pvc, pv := range pvcsMap {
		if pvc == "" || pv == "" {
			t.Fatalf("empty pvc name (%s) or pv string (%s)", pvc, pv)
		}
		if _, ok := pvsMap[pv]; !ok {
			t.Fatalf("pv (%s) not in reverse lookup table", pv)
		}
	}
}
