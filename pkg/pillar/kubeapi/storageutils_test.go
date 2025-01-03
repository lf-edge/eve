// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build kubevirt

package kubeapi

import (
	"testing"
)

func init() {

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
