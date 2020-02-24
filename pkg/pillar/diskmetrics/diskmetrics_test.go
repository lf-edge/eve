// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"os"
	"testing"
)

type diskImgInfo struct {
	diskFile    string
	VirtualSize uint64
	Filename    string
	ClusterSize uint64
	Format      string
	ActualSize  uint64
	DirtyFlag   bool
}

func TestCreateScratchDisk(t *testing.T) {
	testMatrix := map[string]diskImgInfo{
		"qcow disk create": {
			diskFile:    "/tmp/sample1.qcow",
			VirtualSize: 1073741824,
			Format:      "qcow",
		},
		"qcow2 disk create": {
			diskFile:    "/tmp/sample2.qcow2",
			VirtualSize: 1073741824,
			Format:      "qcow2",
		},
		"raw disk create": {
			diskFile:    "/tmp/sample3.raw",
			VirtualSize: 1073741824,
			Format:      "raw",
		},
		"vmdk disk create": {
			diskFile:    "/tmp/sample4.vmdk",
			VirtualSize: 1073741824,
			Format:      "vmdk",
		},
		"vhdx disk create": {
			diskFile:    "/tmp/sample5.vhdx",
			VirtualSize: 1073741824,
			Format:      "vhdx",
		},
		"qcow (in uppercase) disk create": {
			diskFile:    "/tmp/sample6.qcow",
			VirtualSize: 1073741824,
			Format:      "QCOW",
		},
		"qcow2 (in uppercase) disk create": {
			diskFile:    "/tmp/sample7.qcow2",
			VirtualSize: 1073741824,
			Format:      "QCOW2",
		},
		"raw (in uppercase) disk create": {
			diskFile:    "/tmp/sample8.raw",
			VirtualSize: 1073741824,
			Format:      "RAW",
		},
		"vmdk (in uppercase) disk create": {
			diskFile:    "/tmp/sample9.vmdk",
			VirtualSize: 1073741824,
			Format:      "VMDK",
		},
		"vhdx (in uppercase) disk create": {
			diskFile:    "/tmp/sample10.vhdx",
			VirtualSize: 1073741824,
			Format:      "VHDX",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		err := CreateScratchDisk(test.diskFile, test.Format, test.VirtualSize)
		if err != nil {
			t.Errorf("CreateScratchDisk failed: %v", err)
		} else {
			os.Remove(test.diskFile)
		}
	}
}
