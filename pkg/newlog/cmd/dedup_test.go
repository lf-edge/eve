// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/lf-edge/eve-api/go/logs"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

func TestDeduplicateLogs(t *testing.T) {
	// Create channels
	totalLogs := int(dedupWindowSize.Load() + 50)
	in := make(chan inputEntry, totalLogs)
	distinctLogs := 75
	out := make(chan inputEntry, distinctLogs)

	// Start deduplicateLogs in a goroutine.
	go deduplicateLogs(in, out)

	for i := 0; i < totalLogs; i++ {
		// Use 50 distinct messages
		entry := inputEntry{content: "msg" + strconv.Itoa(i%distinctLogs), severity: "error", appUUID: strconv.Itoa(i)}
		in <- entry
	}
	close(in)

	// Collect output logs.
	var results []inputEntry
	for entry := range out {
		results = append(results, entry)
	}

	if len(results) != distinctLogs {
		t.Fatalf("expected %d output logs, got %d", distinctLogs, len(results))
	}

	for i := 0; i < distinctLogs; i++ {
		expectedMessage := "msg" + strconv.Itoa(i)
		if results[i].content != expectedMessage {
			t.Errorf("at output index %d: expected %q, got %q", i, expectedMessage, results[i].content)
		}
	}
}

func TestDedupWithLocalFile(t *testing.T) {
	// Create a channel to send the log entry to deduplicateLogs
	in := make(chan inputEntry, 10)
	out := make(chan inputEntry, 10)

	// Start deduplicateLogs in a goroutine.
	go deduplicateLogs(in, out)

	go func() {
		// Read local log file
		file, err := os.Open("../testdata/collect/dev.log.keep.397634723")
		if err != nil {
			panic(err)
		}
		defer file.Close()

		// Read lines from the gzip file
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				t.Error(err)
				continue
			}

			var entry logs.LogEntry
			if err = json.Unmarshal(scanner.Bytes(), &entry); err != nil {
				t.Error(err)
				continue
			}

			in <- inputEntry{
				severity:  entry.Severity,
				source:    entry.Source,
				content:   entry.Content,
				pid:       entry.Iid,
				filename:  entry.Filename,
				function:  entry.Function,
				timestamp: entry.Timestamp.String(),
				appUUID:   fmt.Sprint(entry.Msgid),
			}
		}
		close(in)
	}()

	file, err := os.OpenFile("/tmp/deduped_logs", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	for entry := range out {
		timeS, _ := getPtypeTimestamp(entry.timestamp)
		msgid, _ := strconv.Atoi(entry.appUUID)
		mapLog := logs.LogEntry{
			Severity:  entry.severity,
			Source:    entry.source,
			Content:   entry.content,
			Iid:       entry.pid,
			Filename:  entry.filename,
			Function:  entry.function,
			Timestamp: timeS,
			Msgid:     uint64(msgid),
		}

		mapJentry, _ := json.Marshal(&mapLog)
		logline := string(mapJentry) + "\n"
		_, err = file.WriteString(logline)
		if err != nil {
			t.Error(err)
		}
	}

	t.Logf("Total num deduped logs: %d", numDedupedLogs)
}

func TestDoMoveCompressFile(t *testing.T) {
	logFileInfo := fileChanInfo{
		tmpfile:   "../testdata/collect/dev.log.keep.397634723",
		isApp:     false,
		notUpload: false, // treat as if it was uploaded to see how the filtering measures work
	}

	agentPid := os.Getpid()
	formatter := logrus.JSONFormatter{DisableTimestamp: true}
	logrus.SetFormatter(&formatter)
	logrus.SetLevel(logrus.TraceLevel)
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, agentPid)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// FILTERING PARAMS:
	filenameFilter.Store(map[string]any{
		// "/pillar/types/zedroutertypes.go:1079": nil,
	})
	logsToCount.Store([]string{
		"/pillar/types/zedroutertypes.go:1079",
	})

	// set uploadDevDir to a local path
	uploadDevDir = "/tmp"

	doMoveCompressFile(ps, logFileInfo)

	t.Logf("filterSuppressedLogs: %d", filterSuppressedLogs)
	t.Logf("counterSuppressedLogs: %d", counterSuppressedLogs)
	t.Logf("Total num deduped logs: %d", numDedupedLogs)

	// Count the number of lines in the original log file.
	fOrig, err := os.Open(logFileInfo.tmpfile)
	if err != nil {
		t.Errorf("failed to open original file: %v", err)
	} else {
		defer fOrig.Close()
		scanner := bufio.NewScanner(fOrig)
		origLineCount := 0
		for scanner.Scan() {
			origLineCount++
		}
		if err = scanner.Err(); err != nil {
			t.Errorf("error scanning original file: %v", err)
		}
		t.Logf("Total number of lines in original file: %d", origLineCount)
	}
}

func BenchmarkDoMoveCompressFile(b *testing.B) {
	logFileInfo := fileChanInfo{
		tmpfile: "../testdata/collect/dev.log.keep.397634723",
		isApp:   false,
	}

	agentPid := os.Getpid()
	formatter := logrus.JSONFormatter{DisableTimestamp: true}
	logrus.SetFormatter(&formatter)
	logrus.SetLevel(logrus.DebugLevel)
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, agentName, agentPid)
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	b.Run("only compression", func(b *testing.B) {
		logFileInfo.notUpload = true // filtering and deduplication are only applied to the logs to be uploaded
		// set keepSentDir to a local path
		keepSentDir = "/tmp"

		// Report memory allocations.
		b.ReportAllocs()

		// Run the benchmark.
		for i := 0; i < b.N; i++ {
			doMoveCompressFile(ps, logFileInfo)
		}
	})

	b.Run("filtering and deduplication does nothing", func(b *testing.B) {
		logFileInfo.notUpload = false // filtering and deduplication are only applied to the logs to be uploaded
		// set uploadDevDir to a local path
		uploadDevDir = "/tmp"

		// FILTERING PARAMS:
		filenameFilter.Store(map[string]any{
			// "/pillar/types/zedroutertypes.go:1079": nil,
		})
		logsToCount.Store([]string{
			// "/pillar/types/zedroutertypes.go:1079",
		})
		dedupWindowSize.Store(0)

		// Report memory allocations.
		b.ReportAllocs()

		// Run the benchmark.
		for i := 0; i < b.N; i++ {
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
		filenameFilter.Store(map[string]any{
			"/pillar/types/zedroutertypes.go:1079": nil,
		})
		logsToCount.Store([]string{
			"/pillar/types/zedroutertypes.go:1079",
		})
		dedupWindowSize.Store(100)

		// Report memory allocations.
		b.ReportAllocs()

		// Run the benchmark.
		for i := 0; i < b.N; i++ {
			doMoveCompressFile(ps, logFileInfo)
		}

		b.Logf("filterSuppressedLogs: %d", filterSuppressedLogs)
		b.Logf("counterSuppressedLogs: %d", counterSuppressedLogs)
		b.Logf("Total num deduped logs: %d", numDedupedLogs)
	})
}
