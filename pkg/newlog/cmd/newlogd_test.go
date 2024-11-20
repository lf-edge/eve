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
