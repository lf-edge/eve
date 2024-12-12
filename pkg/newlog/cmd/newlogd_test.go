// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	. "github.com/onsi/gomega"
)

func TestGzipParsing(t *testing.T) {
	g := NewWithT(t)

	// Test the gzip parsing function
	keepSentDir = "../testdata/keepSentQueue"
	oldestLogEntry, err := getOldestLog()

	g.Expect(err).To(BeNil())
	g.Expect(oldestLogEntry).NotTo(BeNil())
	t.Logf("latestLogEntry: %v\n", oldestLogEntry)

	g.Expect(oldestLogEntry.Content).To(Equal("memlogd started"))

	logmetrics.OldestSavedDeviceLog = time.Unix(
		oldestLogEntry.Timestamp.Seconds, int64(oldestLogEntry.Timestamp.Nanos))
	t.Log("OldestSavedDeviceLog: ", logmetrics.OldestSavedDeviceLog)
}

func TestGetTimestampFromGzipName(t *testing.T) {
	g := NewWithT(t)

	comparisonMap := map[string]time.Time{
		"app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.1731935033496.gz": time.Unix(0, 1731935033496*int64(time.Millisecond)),
		"dev.log.keep.1731491904032.gz":                                 time.Unix(0, 1731491904032*int64(time.Millisecond)),
		"dev.log.keep.1731491932618.gz":                                 time.Unix(0, 1731491932618*int64(time.Millisecond)),
		"dev.log.keep.1731491940142.gz":                                 time.Unix(0, 1731491940142*int64(time.Millisecond)),
	}

	keepSentDir = "../testdata/keepSentQueue"
	files, err := os.ReadDir(keepSentDir)
	g.Expect(err).To(BeNil())

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		timestamp, err := types.GetTimestampFromGzipName(file.Name())
		g.Expect(err).To(BeNil())
		g.Expect(timestamp).To(Equal(comparisonMap[file.Name()]))
	}
}

func TestFindMovePrevLogFiles(t *testing.T) {
	g := NewWithT(t)

	collectDir = "../testdata/collect"

	disableLogsForApp := true
	appD := appDomain{
		disableLogs: disableLogsForApp,
	}
	domainUUID.Store("8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d", appD)

	movefileChan := make(chan fileChanInfo, 5)
	findMovePrevLogFiles(movefileChan)

	g.Eventually(movefileChan).Should(HaveLen(3))

	var file1, file2, file3 fileChanInfo
	select {
	case file1 = <-movefileChan:
	case <-time.After(time.Second):
		t.Fatal("Expected fileChanInfo not received")
	}

	select {
	case file2 = <-movefileChan:
	case <-time.After(time.Second):
		t.Fatal("Expected fileChanInfo not received")
	}

	select {
	case file3 = <-movefileChan:
	case <-time.After(time.Second):
		t.Fatal("Expected fileChanInfo not received")
	}

	files := []fileChanInfo{file1, file2, file3}
	expectedFiles := map[string]bool{
		"../testdata/collect/dev.log.keep.397634723":                                     true,
		"../testdata/collect/dev.log.upload.815590695":                                   false,
		"../testdata/collect/app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.1731935033496": disableLogsForApp,
	}

	for _, file := range files {
		expectedNotUpload, exists := expectedFiles[file.tmpfile]
		g.Expect(exists).To(BeTrue())
		g.Expect(file.notUpload).To(Equal(expectedNotUpload))

		getFileInfo(file)
	}
}

func TestGetFileInfo(t *testing.T) {
	g := NewWithT(t)

	tests := []struct {
		name          string
		fileChanInfo  fileChanInfo
		expectedDir   string
		expectedAppID string
	}{
		{
			name: "Device log file for upload",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/dev.log.upload.123456",
				isApp:     false,
				notUpload: false,
			},
			expectedDir:   uploadDevDir,
			expectedAppID: "",
		},
		{
			name: "Device log file to keep",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/dev.log.keep.123456",
				isApp:     false,
				notUpload: true,
			},
			expectedDir:   keepSentDir,
			expectedAppID: "",
		},
		{
			name: "App log file for upload",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.123456",
				isApp:     true,
				notUpload: false,
			},
			expectedDir:   uploadAppDir,
			expectedAppID: "8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d",
		},
		{
			name: "App log file to keep",
			fileChanInfo: fileChanInfo{
				tmpfile:   "../testdata/collect/app.8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d.log.123456",
				isApp:     true,
				notUpload: true,
			},
			expectedDir:   keepSentDir,
			expectedAppID: "8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirName, appuuid := getFileInfo(tt.fileChanInfo)
			g.Expect(dirName).To(Equal(tt.expectedDir))
			g.Expect(appuuid).To(Equal(tt.expectedAppID))
		})
	}
}
