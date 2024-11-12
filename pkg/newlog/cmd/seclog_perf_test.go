// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/sirupsen/logrus"
)

var (
	runs         = []int{10, 20, 30, 40, 50, 100, 200, 500}
	growth       = 10
	keyCacheBase = 10000
	keyCacheMax  = 500000
)

func growLogContents(filename string, times int) error {
	content, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var newContent []byte
	for i := 0; i < times; i++ {
		newContent = append(newContent, content...)
	}

	err = os.WriteFile(filename, newContent, 0777)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

func processVerifyLogs(t *testing.T) {
	// get the log gzipped file path
	allLogs := listFilesInDir(uploadDevDir)
	for _, logGzipped := range allLogs {
		rf, err := os.Open(logGzipped)
		if err != nil {
			t.Fatalf("Failed to open %s: %s", logGzipped, err)
		}
		defer rf.Close()

		gr, err := gzip.NewReader(rf)
		if err != nil {
			t.Fatalf("Failed to create gzip reader: %s", err)
		}
		defer gr.Close()

		// read the batch metadata from gzipped metadata.
		aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
		if err != nil {
			t.Fatalf("Failed to read secure log metadata from %s: %s", logGzipped, err)
		}

		logs := make([][]byte, 0)
		scanner := bufio.NewScanner(gr)
		for scanner.Scan() {
			if !json.Valid(scanner.Bytes()) {
				t.Fatalf("Invalid JSON: %s", scanner.Text())
			}
			logs = append(logs, append([]byte(nil), scanner.Bytes()...))
		}

		verifKey := evolveKey(sk0Test, keyIter)
		res := fssAggVer(verifKey, aggSig, logs)
		if !res {
			t.Fatalf("Failed to verify logs")
		}
	}
}

func processVerifyLogsWithCachedKeys(t *testing.T) {
	// get the log gzipped file path
	allLogs := listFilesInDir(uploadDevDir)
	for _, logGzipped := range allLogs {
		rf, err := os.Open(logGzipped)
		if err != nil {
			t.Fatalf("Failed to open %s: %s", logGzipped, err)
		}
		defer rf.Close()

		gr, err := gzip.NewReader(rf)
		if err != nil {
			t.Fatalf("Failed to create gzip reader: %s", err)
		}
		defer gr.Close()

		// read the batch metadata from gzipped metadata.
		aggSig, keyIter, err := getLogVerficiationMetadata(gr.Comment)
		if err != nil {
			t.Fatalf("Failed to read secure log metadata from %s: %s", logGzipped, err)
		}

		logs := make([][]byte, 0)
		scanner := bufio.NewScanner(gr)
		for scanner.Scan() {
			if !json.Valid(scanner.Bytes()) {
				t.Fatalf("Invalid JSON: %s", scanner.Text())
			}
			logs = append(logs, append([]byte(nil), scanner.Bytes()...))
		}

		// shortcut?
		if keyIter > uint64(keyCacheBase) {
			keyIndex := (keyIter / uint64(keyCacheBase)) * uint64(keyCacheBase)
			keyFile := fmt.Sprintf("key_%d", keyIndex)

			// read the key from the file
			startingKey, err := os.ReadFile(keyFile)
			if err != nil {
				t.Fatalf("Failed to read cached key: %s", err)
			}

			verifKey := evolveKey(startingKey, (keyIter - keyIndex))
			res := fssAggVer(verifKey, aggSig, logs)
			if !res {
				t.Fatalf("Failed to verify log with cached key")
			}
		} else {
			verifKey := evolveKey(sk0Test, keyIter)
			res := fssAggVer(verifKey, aggSig, logs)
			if !res {
				t.Fatalf("Failed to verify logs")
			}
		}
	}
}

func processLogs(t *testing.T) {
	// get the log gzipped file path
	allLogs := listFilesInDir(uploadDevDir)
	for _, logGzipped := range allLogs {
		rf, err := os.Open(logGzipped)
		if err != nil {
			t.Fatalf("Failed to open %s: %s", logGzipped, err)
		}
		defer rf.Close()

		gr, err := gzip.NewReader(rf)
		if err != nil {
			t.Fatalf("Failed to create gzip reader: %s", err)
		}
		defer gr.Close()

		// just read the logs
		logs := make([][]byte, 0)
		scanner := bufio.NewScanner(gr)
		for scanner.Scan() {
			if !json.Valid(scanner.Bytes()) {
				t.Fatalf("Invalid JSON: %s", scanner.Text())
			}
			logs = append(logs, append([]byte(nil), scanner.Bytes()...))
		}
	}
}

func cacheKeys() {
	// cache the keys
	for i := keyCacheBase; i <= keyCacheMax; i += keyCacheBase {
		key := evolveKey(sk0Test, uint64(i))
		fd, err := os.Create(fmt.Sprintf("key_%d", i))
		if err != nil {
			fmt.Printf("Failed to create key file: %s", err)
		}

		_, _ = fd.Write(key)
		fd.Close()
	}
}

func removeCachedKeys() {
	// cache the keys
	for i := keyCacheBase; i <= keyCacheMax; i += keyCacheBase {
		os.Remove(fmt.Sprintf("key_%d", i))
	}
}

func TestSecureLogAggregationPerformance(t *testing.T) {
	if os.Getenv("RUN_SEC_LOG_PERF_TEST") == "" {
		t.Skip("Skipping performance test")
	}

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	secLog.keyIter = 0
	secLog.key = sk0Test

	var fileinfo fileChanInfo
	var secureLogTotalTime, nonSecureLogTotalTime time.Duration
	for _, run := range runs {
		for i := 0; i < run; i++ {
			scr := logFile
			dst := path.Join(collectDir, "dev.log.sample")
			copyFile(scr, dst)

			// grow the log contents for better performance testing
			err := growLogContents(dst, growth)
			if err != nil {
				t.Fatalf("Failed to grow log contents: %s", err)
			}

			fileinfo.notUpload = true
			fileinfo.tmpfile = dst
			fileinfo.inputSize = 0

			startSecureLog := time.Now()
			doMoveCompressFileSecure(ps, fileinfo)
			secureLogTotalTime += time.Since(startSecureLog)

			// non-secure log aggregation
			scr = logFile
			dst = path.Join(collectDir, "dev.log.sample")
			copyFile(scr, dst)

			// grow the log contents for better performance testing
			err = growLogContents(dst, growth)
			if err != nil {
				t.Fatalf("Failed to grow log contents: %s", err)
			}

			fileinfo.notUpload = true
			fileinfo.tmpfile = dst
			fileinfo.inputSize = 0

			startNonSecureLog := time.Now()
			doMoveCompressFile(ps, fileinfo)
			nonSecureLogTotalTime += time.Since(startNonSecureLog)
		}

		// Calculate averages
		secureAvg := int(secureLogTotalTime.Microseconds()) / run
		nonSecureAvg := int(nonSecureLogTotalTime.Microseconds()) / run
		performanceCost := secureAvg - nonSecureAvg
		performanceCostPercentage := (float64(performanceCost) / float64(nonSecureAvg)) * 100

		file, err := os.OpenFile("fssaggsig_timing_results.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Error creating CSV file %v", err)
		}
		defer file.Close()
		writer := csv.NewWriter(file)

		stat, _ := file.Stat()
		if stat.Size() == 0 {
			_ = writer.Write([]string{"Test Run", "Average Secure Time (us)", "Average Non-Secure Time (us)", "Performance Cost (us)", "Performance Overhead (%)"})
		}

		_ = writer.Write([]string{
			fmt.Sprintf("%d", run),
			fmt.Sprintf("%d", secureAvg),
			fmt.Sprintf("%d", nonSecureAvg),
			fmt.Sprintf("%d", performanceCost),
			fmt.Sprintf("%.2f", performanceCostPercentage),
		})

		writer.Flush()
	}
}

func TestSecureLogVerificationPerformance(t *testing.T) {
	if os.Getenv("RUN_SEC_LOG_PERF_TEST") == "" {
		t.Skip("Skipping performance test")
	}

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	secLog.keyIter = 0
	secLog.key = sk0Test

	var fileinfo fileChanInfo
	var secureLogTotalTime, nonSecureLogTotalTime time.Duration
	for _, run := range runs {
		for i := 0; i < run; i++ {
			makeTestDirs()

			scr := logFile
			dst := path.Join(collectDir, "dev.log.sample")
			copyFile(scr, dst)

			// grow the log contents for better performance testing
			err := growLogContents(dst, growth)
			if err != nil {
				t.Fatalf("Failed to grow log contents: %s", err)
			}

			fileinfo.notUpload = true
			fileinfo.tmpfile = dst
			fileinfo.inputSize = 0
			doMoveCompressFileSecure(ps, fileinfo)

			startSecureLog := time.Now()
			processVerifyLogs(t)
			secureLogTotalTime += time.Since(startSecureLog)

			removeTestDirs()
			makeTestDirs()

			// non-secure log verification
			scr = logFile
			dst = path.Join(collectDir, "dev.log.sample")
			copyFile(scr, dst)

			// grow the log contents for better performance testing
			err = growLogContents(dst, growth)
			if err != nil {
				t.Fatalf("Failed to grow log contents: %s", err)
			}

			fileinfo.notUpload = true
			fileinfo.tmpfile = dst
			fileinfo.inputSize = 0

			doMoveCompressFile(ps, fileinfo)
			startNonSecureLog := time.Now()
			processLogs(t)
			nonSecureLogTotalTime += time.Since(startNonSecureLog)

			removeTestDirs()
		}

		// Calculate averages
		secureAvg := int(secureLogTotalTime.Microseconds()) / run
		nonSecureAvg := int(nonSecureLogTotalTime.Microseconds()) / run
		performanceCost := secureAvg - nonSecureAvg
		performanceCostPercentage := (float64(performanceCost) / float64(nonSecureAvg)) * 100

		file, err := os.OpenFile("fssaggver_timing_results.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Error creating CSV file %v", err)
		}
		defer file.Close()
		writer := csv.NewWriter(file)

		stat, _ := file.Stat()
		if stat.Size() == 0 {
			_ = writer.Write([]string{"Test Run", "Average Secure Time (us)", "Average Non-Secure Time (us)", "Performance Cost (us)", "Performance Overhead (%)"})
		}

		_ = writer.Write([]string{
			fmt.Sprintf("%d", run),
			fmt.Sprintf("%d", secureAvg),
			fmt.Sprintf("%d", nonSecureAvg),
			fmt.Sprintf("%d", performanceCost),
			fmt.Sprintf("%.2f", performanceCostPercentage),
		})

		writer.Flush()
	}
}

func TestSecureLogCachedKeysVerificationPerformance(t *testing.T) {
	if os.Getenv("RUN_SEC_LOG_PERF_TEST") == "" {
		t.Skip("Skipping performance test")
	}

	logger := logrus.StandardLogger()
	log := base.NewSourceLogObject(logger, "seclog_test", os.Getpid())
	ps := pubsub.New(&pubsub.EmptyDriver{}, logger, log)

	// cache the keys first, this is not secure, just for testing,
	// in real world, the cached keys should be securely stored just like
	// the initial key.
	cacheKeys()
	defer removeCachedKeys()

	// setup the test environment
	makeTestDirs()
	defer removeTestDirs()

	secLog.keyIter = 0
	secLog.key = sk0Test

	var fileinfo fileChanInfo
	var secureLogTotalTime, nonSecureLogTotalTime time.Duration
	for _, run := range runs {
		for i := 0; i < run; i++ {
			makeTestDirs()

			scr := logFile
			dst := path.Join(collectDir, "dev.log.sample")
			copyFile(scr, dst)

			// grow the log contents for better performance testing
			err := growLogContents(dst, growth)
			if err != nil {
				t.Fatalf("Failed to grow log contents: %s", err)
			}

			fileinfo.notUpload = true
			fileinfo.tmpfile = dst
			fileinfo.inputSize = 0
			doMoveCompressFileSecure(ps, fileinfo)

			startSecureLog := time.Now()
			processVerifyLogsWithCachedKeys(t)
			secureLogTotalTime += time.Since(startSecureLog)

			removeTestDirs()
			makeTestDirs()

			// non-secure log verification
			scr = logFile
			dst = path.Join(collectDir, "dev.log.sample")
			copyFile(scr, dst)

			// grow the log contents for better performance testing
			err = growLogContents(dst, growth)
			if err != nil {
				t.Fatalf("Failed to grow log contents: %s", err)
			}

			fileinfo.notUpload = true
			fileinfo.tmpfile = dst
			fileinfo.inputSize = 0

			doMoveCompressFile(ps, fileinfo)
			startNonSecureLog := time.Now()
			processLogs(t)
			nonSecureLogTotalTime += time.Since(startNonSecureLog)

			removeTestDirs()
		}

		// Calculate averages
		secureAvg := int(secureLogTotalTime.Microseconds()) / run
		nonSecureAvg := int(nonSecureLogTotalTime.Microseconds()) / run
		performanceCost := secureAvg - nonSecureAvg
		performanceCostPercentage := (float64(performanceCost) / float64(nonSecureAvg)) * 100

		fileName := fmt.Sprintf("fssaggver_cached_keys_%d_timing_results.csv", keyCacheBase)
		file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatalf("Error creating CSV file %v", err)
		}
		defer file.Close()
		writer := csv.NewWriter(file)

		stat, _ := file.Stat()
		if stat.Size() == 0 {
			_ = writer.Write([]string{"Test Run", "Average Secure Time (us)", "Average Non-Secure Time (us)", "Performance Cost (us)", "Performance Overhead (%)"})
		}

		_ = writer.Write([]string{
			fmt.Sprintf("%d", run),
			fmt.Sprintf("%d", secureAvg),
			fmt.Sprintf("%d", nonSecureAvg),
			fmt.Sprintf("%d", performanceCost),
			fmt.Sprintf("%.2f", performanceCostPercentage),
		})

		writer.Flush()
	}
}
