// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

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
