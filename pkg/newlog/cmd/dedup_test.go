// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"os"
	"testing"

	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

func TestDoMoveCompressFile(t *testing.T) {
	g := gomega.NewWithT(t)

	logFileInfo := fileChanInfo{
		tmpfile:   "../testdata/collect/dev.log.keep.397634723",
		isApp:     false,
		notUpload: false, // treat as if it was uploaded to see how the filtering measures work
	}

	logger.SetLevel(logrus.TraceLevel)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// FILTERING PARAMS:
	filenameFilter.Store(map[string]struct{}{
		// "/pillar/types/zedroutertypes.go:1079": {},
	})
	logsToCount.Store([]string{
		"/pillar/types/zedroutertypes.go:1079",
	})
	dedupWindowSize.Store(100)

	// set uploadDevDir to a local path
	uploadDevDir = "/tmp"

	compressedFiles := doMoveCompressFile(ps, logFileInfo)
	g.Expect(len(compressedFiles)).To(gomega.Equal(1))

	t.Logf("filterSuppressedLogs: %d", filterSuppressedLogs)
	t.Logf("counterSuppressedLogs: %d", counterSuppressedLogs)
	t.Logf("Total num deduped logs: %d", numDedupedLogs)

	// Now let's count how many log entries are missing from the compressed file
	var missingMsgidCount int
	var expectedMsgID uint64
	for _, filePath := range compressedFiles {
		f, err := os.Open(filePath)
		if err != nil {
			t.Errorf("failed to open compressed file %q: %v", filePath, err)
			continue
		}
		defer f.Close()

		gr, err := gzip.NewReader(f)
		if err != nil {
			t.Errorf("failed to create gzip reader for %q: %v", filePath, err)
			continue
		}
		defer gr.Close()

		scanner := bufio.NewScanner(gr)
		for scanner.Scan() {
			var entry logs.LogEntry
			if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				t.Errorf("failed to unmarshal JSON from %q: %v", filePath, err)
				continue
			}
			if entry.Msgid != expectedMsgID && expectedMsgID != 0 {
				missingMsgidCount += int(entry.Msgid - expectedMsgID)
			}
			expectedMsgID = entry.Msgid + 1
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("scanner error for %q: %v", filePath, err)
		}
	}

	t.Logf("Total number of log entries with missing msgid: %d", missingMsgidCount)

	g.Expect(missingMsgidCount).To(gomega.Equal(filterSuppressedLogs+counterSuppressedLogs+numDedupedLogs), "The number of missing msgid entries should match the sum of filterSuppressedLogs, counterSuppressedLogs, and numDedupedLogs")
}

func BenchmarkDoMoveCompressFile(b *testing.B) {
	logFileInfo := fileChanInfo{
		tmpfile: "../testdata/collect/dev.log.keep.397634723",
		isApp:   false,
	}

	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	b.Run("only compression", func(b *testing.B) {
		logFileInfo.notUpload = true // filtering and deduplication are only applied to the logs to be uploaded
		// set keepSentDir to a local path
		keepSentDir = "/tmp"

		// Report memory allocations.
		b.ReportAllocs()

		// Run the benchmark.
		for b.Loop() {
			doMoveCompressFile(ps, logFileInfo)
		}
	})

	b.Run("filtering and deduplication does nothing", func(b *testing.B) {
		logFileInfo.notUpload = false // filtering and deduplication are only applied to the logs to be uploaded
		// set uploadDevDir to a local path
		uploadDevDir = "/tmp"

		// FILTERING PARAMS:
		filenameFilter.Store(map[string]struct{}{
			// "/pillar/types/zedroutertypes.go:1079": {},
		})
		logsToCount.Store([]string{
			// "/pillar/types/zedroutertypes.go:1079",
		})
		dedupWindowSize.Store(0)

		// Report memory allocations.
		b.ReportAllocs()

		// Run the benchmark.
		for b.Loop() {
			doMoveCompressFile(ps, logFileInfo)
		}

		b.Logf("filterSuppressedLogs: %d", filterSuppressedLogs)
		b.Logf("counterSuppressedLogs: %d", counterSuppressedLogs)
		b.Logf("Total num deduped logs: %d", numDedupedLogs)
	})

	b.Run("filtering and deduplication does something", func(b *testing.B) {
		logFileInfo.notUpload = false // filtering and deduplication are only applied to the logs to be uploaded
		// set uploadDevDir to a local path
		uploadDevDir = "/tmp"

		// FILTERING PARAMS:
		filenameFilter.Store(map[string]struct{}{
			"/pillar/types/zedroutertypes.go:1079": {},
		})
		logsToCount.Store([]string{
			"/pillar/types/zedroutertypes.go:1079",
		})
		dedupWindowSize.Store(100)

		// Report memory allocations.
		b.ReportAllocs()

		// Run the benchmark.
		for b.Loop() {
			doMoveCompressFile(ps, logFileInfo)
		}

		b.Logf("filterSuppressedLogs: %d", filterSuppressedLogs)
		b.Logf("counterSuppressedLogs: %d", counterSuppressedLogs)
		b.Logf("Total num deduped logs: %d", numDedupedLogs)
	})
}
