// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package diskmetrics

import (
	"os"
	"testing"
)

type diskImgInfo struct {
	diskFile    string
	virtualSize uint64
	format      string
}

func TestCreateScratchDisk(t *testing.T) {
	testMatrix := map[string]diskImgInfo{
		"qcow disk create": {
			diskFile:    "/tmp/sample1.qcow",
			virtualSize: 1073741824,
			format:      "qcow",
		},
		"qcow2 disk create": {
			diskFile:    "/tmp/sample2.qcow2",
			virtualSize: 1073741824,
			format:      "qcow2",
		},
		"raw disk create": {
			diskFile:    "/tmp/sample3.raw",
			virtualSize: 1073741824,
			format:      "raw",
		},
		"vmdk disk create": {
			diskFile:    "/tmp/sample4.vmdk",
			virtualSize: 1073741824,
			format:      "vmdk",
		},
		"vhdx disk create": {
			diskFile:    "/tmp/sample5.vhdx",
			virtualSize: 1073741824,
			format:      "vhdx",
		},
		"qcow (in uppercase) disk create": {
			diskFile:    "/tmp/sample6.qcow",
			virtualSize: 1073741824,
			format:      "QCOW",
		},
		"qcow2 (in uppercase) disk create": {
			diskFile:    "/tmp/sample7.qcow2",
			virtualSize: 1073741824,
			format:      "QCOW2",
		},
		"raw (in uppercase) disk create": {
			diskFile:    "/tmp/sample8.raw",
			virtualSize: 1073741824,
			format:      "RAW",
		},
		"vmdk (in uppercase) disk create": {
			diskFile:    "/tmp/sample9.vmdk",
			virtualSize: 1073741824,
			format:      "VMDK",
		},
		"vhdx (in uppercase) disk create": {
			diskFile:    "/tmp/sample10.vhdx",
			virtualSize: 1073741824,
			format:      "VHDX",
		},
	}
	for testname, test := range testMatrix {
		t.Logf("Running test case %s", testname)
		err := CreateScratchDisk(test.diskFile, test.format, test.virtualSize)
		if err != nil {
			t.Errorf("CreateScratchDisk failed: %v", err)
		} else {
			os.Remove(test.diskFile)
		}
	}
}
