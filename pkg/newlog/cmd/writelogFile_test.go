// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/onsi/gomega"
)

func TestGzipParsing(t *testing.T) {
	t.Parallel()
	g := gomega.NewWithT(t)

	// Test the gzip parsing function
	keepSentDir = "../testdata/keepSentQueue"
	oldestLogEntry, err := getOldestLog()

	g.Expect(err).To(gomega.BeNil())
	g.Expect(oldestLogEntry).NotTo(gomega.BeNil())
	t.Logf("latestLogEntry: %v\n", oldestLogEntry)

	g.Expect(oldestLogEntry.Content).To(gomega.Equal("memlogd started"))

	logmetrics.OldestSavedDeviceLog = time.Unix(
		oldestLogEntry.Timestamp.Seconds, int64(oldestLogEntry.Timestamp.Nanos))
	t.Log("OldestSavedDeviceLog: ", logmetrics.OldestSavedDeviceLog)
}

func TestFindMovePrevLogFiles(t *testing.T) {
	t.Parallel()
	g := gomega.NewWithT(t)

	collectDir = "../testdata/collect"

	disableLogsForApp := true
	appD := appDomain{
		disableLogs: disableLogsForApp,
	}
	domainUUID.Store("8ce1cc69-e1bb-4fe3-9613-e3eb1c5f5c4d", appD)

	movefileChan := make(chan fileChanInfo, 5)
	findMovePrevLogFiles(movefileChan)

	g.Eventually(movefileChan).Should(gomega.HaveLen(3))

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
		g.Expect(exists).To(gomega.BeTrue())
		g.Expect(file.notUpload).To(gomega.Equal(expectedNotUpload))

		getFileInfo(file)
	}
}
